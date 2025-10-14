#!/usr/bin/env python3
"""
Mantis Bug Tracker LDAP Sync Script
Syncs LDAP users to Mantis and manages projects/permissions

IMPORTANT: The Mantis API does not support listing all users.
- MySQL access is REQUIRED for --remove-untracked-users functionality
- Without MySQL, the script will check users individually using /users/username/:username

Dependencies:
- requests
- ldap3  
- pymysql (REQUIRED for --remove-untracked-users, recommended for better performance)

Install with:
pip install requests ldap3 pymysql
"""

import os
import sys
import time
import argparse
import secrets
import string
import requests
from typing import Dict, List, Set, Optional
from ldap3 import Server, Connection, ALL, SUBTREE

# Try to import MySQL connector
try:
    import pymysql
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    print("Note: pymysql not installed. MySQL direct queries disabled. Install with: pip install pymysql")

# Environment variables
MANTIS_URL = os.getenv("MANTIS_URL", "https://tickets.wccomps.org")
MANTIS_API_TOKEN = os.getenv("MANTIS_API_TOKEN")
LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://10.0.0.4")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "cn=core-ldap-svc,dc=ldap,dc=wccomps,dc=org")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=ldap,dc=wccomps,dc=org")
SYNC_TIME = int(os.getenv("SYNC_TIME", "5"))

# MySQL environment variables (optional)
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "mantis")

# Global verbose flag
VERBOSE = False

# Global user cache - shared across sync operations
MANTIS_USER_CACHE = {}

# LDAP group to Mantis role mapping
GROUP_ROLE_MAP = {
    "WCComps_Ticketing_Support": "manager",
    "WCComps_Ticketing_Admin": "administrator"
}

# Mantis role levels (adjust based on your Mantis configuration)
ROLE_LEVELS = {
    "viewer": 10,
    "reporter": 25,
    "updater": 40,
    "developer": 55,
    "manager": 70,
    "administrator": 90
}


class MantisDB:
    """Direct MySQL database access for Mantis (optional, more efficient)"""
    
    def __init__(self, host: str, port: int, user: str, password: str, database: str):
        if not MYSQL_AVAILABLE:
            raise ImportError("pymysql is not installed")
        
        self.connection = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            cursorclass=pymysql.cursors.DictCursor
        )
    
    def get_all_users(self) -> List[Dict]:
        """Get all users from database"""
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT `id`, `username`, `email`, `realname`, `access_level`, `enabled`, `protected` FROM `mantis_user_table`")
            return cursor.fetchall()
    
    def close(self):
        """Close database connection"""
        self.connection.close()


class MantisAPI:
    """Wrapper for Mantis Bug Tracker REST API"""
    
    def __init__(self, base_url: str, api_token: str):
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.headers = {
            "Authorization": api_token,
            "Content-Type": "application/json"
        }
    
    def _request(self, method: str, endpoint: str, **kwargs):
        """Make API request"""
        url = f"{self.base_url}/api/rest{endpoint}"
        
        if VERBOSE:
            from urllib.parse import urlparse
            import json
            
            parsed = urlparse(url)
            
            print(f"\n{'='*60}")
            print(f"[RAW HTTP REQUEST]")
            print(f"{method} {parsed.path}{('?' + parsed.query) if parsed.query else ''} HTTP/1.1")
            print(f"Host: {parsed.netloc}")
            
            # Print headers
            for key, value in self.headers.items():
                # Mask the token for security
                if key == "Authorization":
                    masked_value = value[:20] + "..." if len(value) > 20 else value
                    print(f"{key}: {masked_value}")
                else:
                    print(f"{key}: {value}")
            
            # Print body if present
            if 'json' in kwargs:
                body = json.dumps(kwargs['json'], indent=2)
                print(f"Content-Length: {len(body)}")
                print()
                print(body)
            
            print(f"{'='*60}")
            print(f"Full URL: {url}")
        
        try:
            response = requests.request(method, url, headers=self.headers, **kwargs)
            
            if VERBOSE:
                import json
                print(f"\n{'='*60}")
                print(f"[RAW HTTP RESPONSE]")
                print(f"HTTP/1.1 {response.status_code} {response.reason}")
                
                # Print response headers
                for key, value in response.headers.items():
                    print(f"{key}: {value}")
                
                # Print response body
                if response.text:
                    print()
                    try:
                        print(json.dumps(response.json(), indent=2))
                    except:
                        print(response.text)
                
                print(f"{'='*60}\n")
            
            response.raise_for_status()
            return response.json() if response.text else None
        except requests.exceptions.RequestException as e:
            print(f"\n❌ API Error: {method} {url}")
            print(f"   Status Code: {e.response.status_code if hasattr(e, 'response') else 'N/A'}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"   Response: {e.response.text}")
            if 'json' in kwargs:
                import json
                print(f"   Request Body: {json.dumps(kwargs['json'], indent=2)}")
            raise
    
    def get_issues(self, page_size: int = 50, page: int = 1) -> List[Dict]:
        """Get all issues"""
        return self._request("GET", f"/issues/?page_size={page_size}&page={page}")
    
    def delete_issue(self, issue_id: int):
        """Delete an issue"""
        return self._request("DELETE", f"/issues/{issue_id}")
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username using /users/username/:username endpoint"""
        try:
            result = self._request("GET", f"/users/username/{username}")
            if result and 'users' in result and len(result['users']) > 0:
                return result['users'][0]
            return None
        except Exception as e:
            if VERBOSE:
                print(f"    User {username} not found via API: {e}")
            return None
    
    def delete_user(self, user_id: int):
        """Delete a user"""
        return self._request("DELETE", f"/users/{user_id}")
    
    def create_user(self, username: str, email: str, real_name: str, password: str, access_level: str) -> Dict:
        """Create a new user"""
        data = {
            "username": username,
            "email": email,
            "real_name": real_name,
            "password": password,
            "enabled": True,
            "protected": False
        }
        if access_level:
            data["access_level"] = {"name": access_level}
        return self._request("POST", "/users/", json=data)
    
    def update_user_access(self, user_id: int, access_level: str):
        """Update user access level"""
        data = {"access_level": {"name": access_level}}
        return self._request("PATCH", f"/users/{user_id}", json=data)
    
    def update_user(self, user_id: int, user_name: str, email: str = None, real_name: str = None, access_level: str = None):
        """Update user information"""
        data = {}
        if user_name:
            data["name"] = user_name
            data["user"] = user_name
        if email:
            data["email"] = email
        if real_name:
            data["real_name"] = real_name
        if access_level:
            data["access_level"] = {"name": access_level}
        
        if data:
            return self._request("PATCH", f"/users/{user_id}", json=data)
    
    def get_projects(self) -> List[Dict]:
        """Get all projects"""
        return self._request("GET", "/projects/")
    
    def get_project(self, project_id: int) -> Dict:
        """Get project by ID"""
        return self._request("GET", f"/projects/{project_id}")
    
    def create_project(self, name: str, description: str = "", parent_id: Optional[int] = None) -> Dict:
        """Create a new project (or subproject if parent_id provided)"""
        data = {
            "name": name,
            "description": description,
            "enabled": True,
            "view_state": {"name": "public"}
        }
        if parent_id:
            # Create as subproject by setting parent
            data["parent"] = {"id": parent_id}
        return self._request("POST", "/projects/", json=data)
    
    def add_user_to_project(self, project_id: int, user_id: int = None, username: str = None, access_level: str = "reporter"):
        """Add user to project with specific access level (or update if already exists)"""
        if not user_id and not username:
            raise ValueError("Either user_id or username must be provided")
        
        data = {
            "access_level": {"name": access_level}
        }
        
        # Use username if provided, otherwise use user_id
        if username:
            data["user"] = {"name": username}
        elif user_id:
            data["user"] = {"id": user_id}
        
        # Use PUT to add or update user access
        return self._request("PUT", f"/projects/{project_id}/users/", json=data)
    
    def get_project_users(self, project_id: int) -> List[Dict]:
        """Get users assigned to a project"""
        return self._request("GET", f"/projects/{project_id}/users/")


def generate_random_password(length: int = 16) -> str:
    """Generate a random password"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def get_mysql_connection() -> Optional[MantisDB]:
    """Establish MySQL connection if configured"""
    if not MYSQL_AVAILABLE or not MYSQL_HOST or not MYSQL_USER or not MYSQL_PASSWORD:
        return None
    
    try:
        if VERBOSE:
            print(f"\nConnecting to MySQL database at {MYSQL_HOST}:{MYSQL_PORT}...")
        db = MantisDB(MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE)
        if VERBOSE:
            print("    MySQL connection successful.")
        return db
    except Exception as e:
        print(f"⚠ MySQL connection failed: {e}")
        return None


def load_mantis_users_from_mysql(db: MantisDB) -> Dict[str, Dict]:
    """Load all Mantis users from MySQL into the global cache"""
    global MANTIS_USER_CACHE
    
    print("Fetching users from MySQL database...")
    db_users = db.get_all_users()
    
    MANTIS_USER_CACHE.clear()
    for user in db_users:
        MANTIS_USER_CACHE[user['username']] = {
            'id': user['id'],
            'name': user['username'],
            'email': user.get('email', ''),
            'real_name': user.get('realname', ''),
            'access_level': user.get('access_level'),
            'enabled': user.get('enabled', True),
            'protected': user.get('protected', False)
        }
    
    print(f"Loaded {len(MANTIS_USER_CACHE)} users into cache")
    return MANTIS_USER_CACHE


def get_ldap_users(groups: List[str]) -> Dict[str, Dict]:
    """
    Query LDAP and return users from specified groups
    Returns: {username: {"email": email, "name": name, "groups": [group1, group2]}}
    """
    if not LDAP_BIND_PASSWORD:
        print("Error: LDAP_BIND_PASSWORD not set")
        sys.exit(1)
    
    print(f"Connecting to LDAP: {LDAP_SERVER}")
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, LDAP_BIND_DN, LDAP_BIND_PASSWORD, auto_bind=True)
    
    user_map = {}
    
    for group in groups:
        print(f"Searching for group: {group}")
        # Search for users who are members of this group
        # The memberOf attribute contains full DN like: cn=WCComps_Ticketing_Support,ou=groups,dc=ldap,dc=wccomps,dc=org
        search_filter = f"(memberOf=cn={group},ou=groups,{LDAP_BASE_DN})"
        
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'cn', 'mail', 'displayName', 'memberOf']
        )
        
        print(f"  LDAP returned {len(conn.entries)} entries")
        
        for entry in conn.entries:
            # Use sAMAccountName as the primary username
            username = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else None
            if not username:
                # Fallback to cn if sAMAccountName not present
                username = str(entry.cn) if hasattr(entry, 'cn') else None
            
            if not username:
                print(f"  Skipping entry without username: {entry.entry_dn}")
                continue
            
            email = str(entry.mail) if hasattr(entry, 'mail') else f"{username}@wccomps.org"
            
            # Prefer displayName, fall back to cn, then username
            if hasattr(entry, 'displayName') and entry.displayName:
                name = str(entry.displayName)
            elif hasattr(entry, 'cn') and entry.cn:
                name = str(entry.cn)
            else:
                name = username
            
            if username not in user_map:
                user_map[username] = {
                    "email": email,
                    "name": name,
                    "groups": []
                }
            
            user_map[username]["groups"].append(group)
            print(f"  Found user: {username} ({name})")
        
        print(f"  Total users in {group}: {len([u for u in user_map.values() if group in u['groups']])} users")
    
    conn.unbind()
    return user_map


def clean_tickets(api: MantisAPI):
    """Delete all existing tickets"""
    print("\n=== Starting Ticket Cleanup ===")
    
    while True:
        try:
            issues = api.get_issues(page_size=100)
            
            if not issues or 'issues' not in issues or len(issues['issues']) == 0:
                print("All tickets cleaned!")
                break
            
            for issue in issues['issues']:
                issue_id = issue['id']
                print(f"  Deleting issue #{issue_id}")
                try:
                    api.delete_issue(issue_id)
                except Exception as e:
                    print(f"    Error deleting issue #{issue_id}: {e}")
            
            print(f"Deleted {len(issues['issues'])} issues, checking for more...")
            
        except Exception as e:
            print(f"Error during cleanup: {e}")
            break
    
    print("=== Ticket Cleanup Complete ===\n")


def sync_users(api: MantisAPI):
    """Sync LDAP users to Mantis - create/update users and assign to projects"""
    global MANTIS_USER_CACHE
    
    print("\n=== Starting User Sync ===")
    
    # Get LDAP users
    ldap_users = get_ldap_users(list(GROUP_ROLE_MAP.keys()) + ["BlueTeam"])
    print(f"\nFound {len(ldap_users)} unique users in LDAP")
    
    # Load Mantis users if cache is empty
    if not MANTIS_USER_CACHE:
        db = get_mysql_connection()
        if db:
            load_mantis_users_from_mysql(db)
            db.close()
        else:
            print("\n⚠ MySQL not configured. Will check users individually via API.")
            print("  For better performance, set MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD")
    
    # Get or create parent project "Competitions"
    print("\nChecking for parent project 'Competitions'...")
    projects_response = api.get_projects()
    projects = {p['name']: p for p in projects_response.get('projects', [])}
    
    competitions_project = None
    if "Competitions" in projects:
        competitions_project = projects["Competitions"]
        print(f"  Found existing project: Competitions (ID: {competitions_project['id']})")
    else:
        print("  Creating parent project: Competitions")
        result = api.create_project("Competitions", "Parent project for competition teams")
        competitions_project = result.get('project')
        print(f"  Created project: Competitions (ID: {competitions_project['id']})")
    
    # Process each LDAP user
    for username, user_info in ldap_users.items():
        print(f"\nProcessing user: {username}")

        access_level = "reporter"  # default
        user_info["blue_team"] = False
        if username.lower().startswith("team") or username.lower().startswith("blue"):
            user_info["blue_team"] = True
            access_level = None

        for group in user_info["groups"]:
            if group in GROUP_ROLE_MAP:
                role = GROUP_ROLE_MAP[group]
                if ROLE_LEVELS.get(role, 0) > ROLE_LEVELS.get(access_level, 0):
                    access_level = role
        
        # Create or update user in Mantis
        user_id = None
        if username in MANTIS_USER_CACHE:
            # User found in cache
            user_id = MANTIS_USER_CACHE[username]['id']
            cached_user = MANTIS_USER_CACHE[username]
            
            # Check if we need to update any fields
            needs_update = False
            updates = {}
            if cached_user.get('email') != user_info['email']:
                needs_update = True
                updates['email'] = user_info['email']
            
            if cached_user.get('real_name') != user_info['name']:
                needs_update = True
                updates['real_name'] = user_info['name']
            
            # Always update access level
            updates['access_level'] = access_level
            needs_update = True
            
            if needs_update:
                print(f"  User exists (ID: {user_id}), updating metadata and access level to {access_level}")
                try:
                    api.update_user(user_id, username, **updates)
                    # Update cache
                    MANTIS_USER_CACHE[username].update({
                        'email': user_info['email'],
                        'real_name': user_info['name'],
                        'access_level': access_level
                    })
                except Exception as e:
                    print(f"    Error updating user: {e}")
            else:
                print(f"  User exists (ID: {user_id}), no updates needed")
        else:
            # User not in cache, check via API
            print(f"  Checking if user exists via API...")
            existing_user = api.get_user_by_username(username)
            if existing_user:
                user_id = existing_user['id']
                print(f"  User exists (ID: {user_id}), updating metadata and access level to {access_level}")
                try:
                    api.update_user(
                        user_id,
                        username,
                        email=user_info['email'],
                        real_name=user_info['name'],
                        access_level=access_level
                    )
                    # Add to cache
                    MANTIS_USER_CACHE[username] = {
                        'id': user_id,
                        'name': username,
                        'email': user_info['email'],
                        'real_name': user_info['name'],
                        'access_level': access_level,
                        'enabled': True,
                        'protected': False
                    }
                except Exception as e:
                    print(f"    Error updating user: {e}")
            else:
                # User doesn't exist, create them
                print(f"  Creating new user with role: {access_level}")
                password = generate_random_password()
                try:
                    result = api.create_user(
                        username=username,
                        email=user_info["email"],
                        real_name=user_info["name"],
                        password=password,
                        access_level=access_level
                    )
                    user_id = result.get('user', {}).get('id')
                    print(f"    Created user (ID: {user_id})")
                    
                    # Add to cache
                    MANTIS_USER_CACHE[username] = {
                        'id': user_id,
                        'name': username,
                        'email': user_info['email'],
                        'real_name': user_info['name'],
                        'access_level': access_level,
                        'enabled': True,
                        'protected': False
                    }
                except Exception as e:
                    print(f"    Error creating user: {e}")
                    continue
        
        # Handle BlueTeam members - create team projects
        if "BlueTeam" in user_info["groups"] and user_id:
            # Extract team number from username (e.g., blue01 -> team01)
            if user_info["blue_team"]:
                team_num = username[4:]  # Get everything after "team"
                team_project_name = f"team{team_num}"
                
                print(f"  BlueTeam member detected, checking for project: {team_project_name}")
                
                # Check if team project exists
                if team_project_name not in projects:
                    print(f"    Creating project: {team_project_name}")
                    try:
                        result = api.create_project(
                            name=team_project_name,
                            description=f"Project for {team_project_name}",
                            parent_id=competitions_project['id']
                        )
                        team_project = result.get('project')
                        projects[team_project_name] = team_project
                        print(f"    Created project (ID: {team_project['id']})")
                    except Exception as e:
                        print(f"    Error creating project: {e}")
                        continue
                else:
                    team_project = projects[team_project_name]
                    print(f"    Project exists (ID: {team_project['id']})")
                
                # Add user as reporter to their team project using user_id
                try:
                    print(f"    Adding user (ID: {user_id}) as reporter to {team_project_name}")
                    api.add_user_to_project(team_project['id'], user_id=user_id, access_level="reporter")
                    print(f"        Successfully added {username} to {team_project_name}")
                except Exception as e:
                    print(f"    Error adding user to project: {e}")
    
    print("\n=== User Sync Complete ===\n")


def remove_untracked_users(api: MantisAPI):
    """Delete users in Mantis that are not in LDAP"""
    global MANTIS_USER_CACHE
    
    print("\n=== Starting Untracked User Removal ===")
    
    # Must have MySQL to get full user list
    if not MYSQL_AVAILABLE or not MYSQL_HOST or not MYSQL_USER or not MYSQL_PASSWORD:
        print("✗ Error: --remove-untracked-users requires MySQL access to list all users")
        print("  Set MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD environment variables")
        if not MYSQL_AVAILABLE:
            print("  Install pymysql: pip install pymysql")
        return
    
    # Reload user cache from MySQL to ensure we have the latest
    db = get_mysql_connection()
    if not db:
        print("✗ Failed to connect to MySQL")
        return
    
    load_mantis_users_from_mysql(db)
    db.close()
    
    # Get current LDAP users
    ldap_users = get_ldap_users(list(GROUP_ROLE_MAP.keys()))
    print(f"Found {len(ldap_users)} users in LDAP")
    
    # Find users to delete
    users_to_delete = []
    protected_users = ['administrator']  # List of usernames to never delete
    
    for mantis_username, mantis_user in MANTIS_USER_CACHE.items():
        # Skip if user is in LDAP
        if mantis_username in ldap_users:
            continue
        
        # Skip protected users
        if mantis_username in protected_users:
            print(f"  Skipping protected user: {mantis_username}")
            continue
        
        # Skip if user is protected in Mantis
        if mantis_user.get('protected', False):
            print(f"  Skipping protected user: {mantis_username} (ID: {mantis_user['id']})")
            continue
        
        users_to_delete.append(mantis_user)
    
    if users_to_delete:
        print(f"\nFound {len(users_to_delete)} users to delete:")
        for user in users_to_delete:
            print(f"  - {user['name']} (ID: {user['id']}, {user.get('email', 'no email')})")
        
        confirm = input(f"\nDelete these {len(users_to_delete)} users? (yes/no): ").strip().lower()
        
        if confirm == 'yes':
            for user in users_to_delete:
                try:
                    print(f"  Deleting user: {user['name']} (ID: {user['id']})")
                    api.delete_user(user['id'])
                    # Remove from cache
                    if user['name'] in MANTIS_USER_CACHE:
                        del MANTIS_USER_CACHE[user['name']]
                    print(f"        Deleted {user['name']}")
                except Exception as e:
                    print(f"    ✗ Error deleting {user['name']}: {e}")
            print(f"\n    Cleanup complete. Deleted {len(users_to_delete)} users.")
        else:
            print("Cleanup cancelled.")
    else:
        print("No users to delete. All Mantis users are in LDAP or protected.")
    
    print("\n=== Untracked User Removal Complete ===\n")


def main():
    global VERBOSE
    
    parser = argparse.ArgumentParser(description="Mantis Bug Tracker LDAP Sync Tool")
    parser.add_argument("--clean-tickets", action="store_true", help="Delete all existing tickets")
    parser.add_argument("--sync-users", action="store_true", help="Sync LDAP users to Mantis")
    parser.add_argument("--remove-untracked-users", action="store_true", help="Delete Mantis users not in LDAP (requires --sync-users)")
    parser.add_argument("--loop", action="store_true", help="Run continuously at SYNC_TIME interval")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output for debugging")
    parser.add_argument("--test", action="store_true", help="Test API connection and list current users/projects")
    
    args = parser.parse_args()
    
    VERBOSE = args.verbose
    
    # Validate required environment variables
    if not MANTIS_API_TOKEN:
        print("Error: MANTIS_API_TOKEN environment variable not set")
        sys.exit(1)
    
    # Initialize API
    api = MantisAPI(MANTIS_URL, MANTIS_API_TOKEN)
    
    # Test connection
    if args.test:
        print("Testing Mantis API connection...")
        try:
            print("\n=== Testing API Connection ===")
            
            # Test individual user lookup
            print("Testing user lookup endpoint...")
            test_user = api.get_user_by_username("administrator")
            if test_user:
                print(f"    User lookup successful (found: {test_user['name']})")
            else:
                print("⚠ User lookup returned no results (this is normal if 'administrator' doesn't exist)")
            
            # Test projects endpoint
            projects = api.get_projects()
            print(f"    Successfully connected to Mantis API")
            print(f"    Found {len(projects.get('projects', []))} projects")
            
            # Test MySQL connection if configured
            if MYSQL_AVAILABLE and MYSQL_HOST and MYSQL_USER and MYSQL_PASSWORD:
                try:
                    print(f"\n=== Testing MySQL Connection ===")
                    print(f"Connecting to {MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}...")
                    db = MantisDB(MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE)
                    db_users = db.get_all_users()
                    print(f"    MySQL connection successful")
                    print(f"    Found {len(db_users)} users in database")
                    
                    if db_users:
                        print(f"\nShowing first 5 users from MySQL:")
                        for user in db_users[:5]:
                            print(f"  - {user['username']} (ID: {user['id']}) - {user.get('email', 'N/A')}")
                    
                    db.close()
                except Exception as e:
                    print(f"✗ MySQL connection failed: {e}")
            else:
                print(f"\n=== MySQL Status ===")
                if not MYSQL_AVAILABLE:
                    print("✗ pymysql not installed (install with: pip install pymysql)")
                else:
                    print("✗ MySQL environment variables not set")
                    print("  Set MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD to enable MySQL support")
                    print("  Note: MySQL is REQUIRED for --remove-untracked-users functionality")
            
            if projects.get('projects'):
                print("\n=== Existing Projects ===")
                for proj in projects['projects']:
                    parent = f" (parent: {proj.get('parent', {}).get('name', 'None')})" if proj.get('parent') else ""
                    print(f"  - {proj['name']} (ID: {proj['id']}){parent}")
            
        except Exception as e:
            print(f"✗ Connection test failed: {e}")
        sys.exit(0)
    
    # Validate --remove-untracked-users requires --sync-users
    if args.remove_untracked_users and not args.sync_users:
        print("Error: --remove-untracked-users requires --sync-users")
        sys.exit(1)
    
    # Execute based on flags
    if args.loop:
        print(f"Loop mode enabled. Running every {SYNC_TIME} minutes.")
        print("Press Ctrl+C to stop.\n")
        
        try:
            while True:
                # Load user cache at the start of each loop iteration
                if args.sync_users:
                    db = get_mysql_connection()
                    if db:
                        load_mantis_users_from_mysql(db)
                        db.close()
                
                if args.clean_tickets:
                    clean_tickets(api)
                
                if args.sync_users:
                    sync_users(api)
                
                if args.remove_untracked_users:
                    remove_untracked_users(api)
                
                print(f"\nWaiting {SYNC_TIME} minutes until next sync...")
                time.sleep(SYNC_TIME * 60)
        except KeyboardInterrupt:
            print("\nLoop stopped.")
    else:
        # Single run mode
        # Load user cache if sync-users is specified
        if args.sync_users:
            db = get_mysql_connection()
            if db:
                load_mantis_users_from_mysql(db)
                db.close()
        
        if args.clean_tickets:
            clean_tickets(api)
        
        if args.sync_users:
            sync_users(api)
        
        if args.remove_untracked_users:
            remove_untracked_users(api)
    
    if not (args.clean_tickets or args.sync_users or args.remove_untracked_users or args.loop):
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

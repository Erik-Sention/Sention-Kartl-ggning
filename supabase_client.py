import os
from supabase import create_client, Client
from dotenv import load_dotenv
import datetime

# Load environment variables
load_dotenv()

# Initialize Supabase client
supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")
supabase = create_client(supabase_url, supabase_key)

# Create admin client with service role key (for admin operations)
supabase_admin = create_client(supabase_url, supabase_key)

def get_items(category, user_id=None):
    """
    Get items for a specific category
    """
    try:
        # Map category names to what's stored in the database if needed
        category_mapping = {
            'anstalld': 'anstalld',
            'grupp': 'grupp',
            'organisation': 'organisation',
            'foretagsledning': 'foretagsledning',
            'managers': 'managers',
            'supervisors': 'supervisors'
        }
        
        # Use the mapped category or the original if not in mapping
        db_category = category_mapping.get(category, category)
        
        response = supabase.table("items") \
            .select("*") \
            .eq("category", db_category) \
            .order("position") \
            .execute()
            
        return response.data if response.data else []
    except Exception as e:
        print(f"Error getting items: {e}")
        return []

def save_item(text, entity, risk_level, position, category, user_id, rating=None):
    """
    Save an item to the database
    """
    try:
        print(f"Attempting to save item: {text}, {entity}, {risk_level}, {position}, {category}, {user_id}, {rating}")
        
        # Create the item data
        item_data = {
            "text": text,
            "entity": entity,
            "risk_level": risk_level,
            "position": position,
            "category": category,
            "user_id": user_id,
            "rating": rating
        }
        
        print(f"Item data: {item_data}")
        
        # Try to insert the item
        response = supabase.table("items").insert(item_data).execute()
        
        print(f"Save response: {response}")
        
        if hasattr(response, 'error') and response.error:
            print(f"Error saving item: {response.error}")
            return None
            
        return response.data
    except Exception as e:
        print(f"Exception saving item: {e}")
        import traceback
        traceback.print_exc()
        return None

def delete_item(text, entity, risk_level, category):
    """
    Delete an item from the database
    """
    try:
        print(f"Attempting to delete item: {text}, {entity}, {risk_level}, {category}")
        
        # Try to delete the item
        response = supabase.table("items") \
            .delete() \
            .eq("text", text) \
            .eq("entity", entity) \
            .eq("risk_level", risk_level) \
            .eq("category", category) \
            .execute()
            
        print(f"Delete response: {response}")
        
        if hasattr(response, 'error') and response.error:
            print(f"Error deleting item: {response.error}")
            return None
            
        return response.data
    except Exception as e:
        print(f"Exception deleting item: {e}")
        import traceback
        traceback.print_exc()
        return None

def save_all_items(category, items, user_id):
    """
    Save all items for a category at once
    """
    try:
        print(f"Attempting to save all items for category: {category}")
        
        # First, delete all existing items for this category
        delete_response = supabase.table("items") \
            .delete() \
            .eq("category", category) \
            .execute()
            
        print(f"Delete all response: {delete_response}")
        
        if hasattr(delete_response, 'error') and delete_response.error:
            print(f"Error deleting items: {delete_response.error}")
            return False
        
        # If there are no items to save, we're done
        if not items:
            return True
        
        # Prepare all items for insertion
        items_to_insert = []
        for item in items:
            items_to_insert.append({
                "text": item['text'],
                "entity": item['entity'],
                "risk_level": item['risk_level'],
                "position": item['position'],
                "category": category,
                "user_id": user_id,
                "rating": item.get('rating')
            })
        
        # Insert all items at once
        insert_response = supabase.table("items").insert(items_to_insert).execute()
        
        print(f"Insert all response: {insert_response}")
        
        if hasattr(insert_response, 'error') and insert_response.error:
            print(f"Error inserting items: {insert_response.error}")
            return False
            
        return True
    except Exception as e:
        print(f"Exception saving all items: {e}")
        import traceback
        traceback.print_exc()
        return False

def get_user_by_username(username):
    """
    Get a user by username (case insensitive)
    """
    try:
        # Supabase doesn't support ILIKE directly in the client, so we use a workaround
        response = supabase.table("users") \
            .select("*") \
            .execute()
        
        # Filter case-insensitive in Python
        users = [user for user in response.data if user["username"].lower() == username.lower()]
        return users[0] if users else None
    except Exception as e:
        print(f"Error getting user: {e}")
        return None

def create_user(username, email, password, full_name, role="user"):
    """
    Create a new user with Supabase Auth and store additional data
    """
    try:
        print(f"Creating user: {username}, {email}")
        
        # Check if email already exists
        existing_users = supabase_admin.table("users").select("*").eq("email", email).execute()
        if existing_users.data:
            print(f"Email already exists: {email}")
            return None
            
        # Check if username already exists
        existing_usernames = supabase_admin.table("users").select("*").eq("username", username).execute()
        if existing_usernames.data:
            print(f"Username already exists: {username}")
            return None
        
        # First create the auth user
        print("Creating auth user...")
        auth_response = supabase_admin.auth.admin.create_user({
            "email": email,
            "password": password,
            "email_confirm": True  # Auto-confirm email
        })
        
        print(f"Auth user created: {auth_response.user.id}")
        user_id = auth_response.user.id
        
        # Then store additional user data
        print("Storing user data...")
        user_response = supabase_admin.table("users").insert({
            "id": user_id,
            "username": username,
            "email": email,
            "full_name": full_name,
            "role": role
        }).execute()
        
        print(f"User data stored: {user_response.data}")
        
        return user_response.data[0] if user_response.data else None
    except Exception as e:
        print(f"Error creating user: {str(e)}")
        # Print the full exception details for debugging
        import traceback
        traceback.print_exc()
        return None

def update_user(user_id, data):
    """
    Update user data
    """
    try:
        response = supabase_admin.table("users") \
            .update(data) \
            .eq("id", user_id) \
            .execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error updating user: {e}")
        return None

def delete_user(user_id):
    """
    Delete a user
    """
    try:
        # First delete from users table
        supabase_admin.table("users") \
            .delete() \
            .eq("id", user_id) \
            .execute()
        
        # Then delete from auth
        supabase_admin.auth.admin.delete_user(user_id)
        return True
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False

def get_all_users():
    """
    Get all users
    """
    try:
        print("Fetching all users from Supabase...")
        response = supabase_admin.table("users").select("*").execute()
        print(f"Response from Supabase: {response}")
        return response.data if response.data else []
    except Exception as e:
        print(f"Error getting users: {e}")
        import traceback
        traceback.print_exc()
        return []

def count_users_by_role(role):
    """
    Count users with a specific role
    """
    try:
        response = supabase.table("users") \
            .select("id") \
            .eq("role", role) \
            .execute()
        return len(response.data)
    except Exception as e:
        print(f"Error counting users: {e}")
        return 0

def get_supabase_client():
    return supabase

def get_auth_users():
    """
    Get all users from Supabase Auth
    """
    try:
        auth_users_response = supabase.auth.admin.list_users()
        
        # Try different ways to access the users based on the response structure
        if hasattr(auth_users_response, 'users'):
            return auth_users_response.users
        elif isinstance(auth_users_response, list):
            return auth_users_response
        elif hasattr(auth_users_response, 'data'):
            if isinstance(auth_users_response.data, list):
                return auth_users_response.data
            else:
                print(f"auth_users_response.data is not a list: {auth_users_response.data}")
                return []
        else:
            print(f"Could not determine the structure of auth_users_response: {auth_users_response}")
            return []
    except Exception as e:
        print(f"Error getting auth users: {e}")
        import traceback
        traceback.print_exc()
        return []

def is_last_admin(user_id):
    """
    Check if the user is the last admin in the system
    """
    try:
        # Get all admin users
        admins = supabase.table("users").select("id").eq("role", "admin").execute()
        
        # If there's only one admin and it's this user, they're the last admin
        return len(admins.data) == 1 and admins.data[0]["id"] == user_id
    except Exception as e:
        print(f"Error checking if last admin: {e}")
        # Default to True to prevent accidentally removing the last admin
        return True

def check_and_fix_rls_policies():
    """
    Check and fix RLS policies for the items table
    This function should be called during application initialization
    """
    try:
        print("Checking RLS policies for items table...")
        
        # Check if we're using the service role key (which can bypass RLS)
        if not supabase_key.endswith('service_role'):
            print("Warning: Not using service role key, may not be able to modify RLS policies")
            return False
            
        # Try to enable row-level security on the items table
        # This is a SQL query that needs to be executed with the service role
        enable_rls_query = """
        ALTER TABLE items ENABLE ROW LEVEL SECURITY;
        """
        
        # Create policy to allow all authenticated users to select items
        select_policy_query = """
        CREATE POLICY IF NOT EXISTS "Allow authenticated users to select items" 
        ON items FOR SELECT 
        USING (auth.role() = 'authenticated');
        """
        
        # Create policy to allow authenticated users to insert their own items
        insert_policy_query = """
        CREATE POLICY IF NOT EXISTS "Allow authenticated users to insert items" 
        ON items FOR INSERT 
        WITH CHECK (auth.role() = 'authenticated');
        """
        
        # Create policy to allow authenticated users to update their own items
        update_policy_query = """
        CREATE POLICY IF NOT EXISTS "Allow authenticated users to update items" 
        ON items FOR UPDATE 
        USING (auth.role() = 'authenticated');
        """
        
        # Create policy to allow authenticated users to delete their own items
        delete_policy_query = """
        CREATE POLICY IF NOT EXISTS "Allow authenticated users to delete items" 
        ON items FOR DELETE 
        USING (auth.role() = 'authenticated');
        """
        
        # Execute the queries
        try:
            supabase.postgrest.schema('public').execute(enable_rls_query)
            print("Enabled RLS on items table")
        except Exception as e:
            print(f"Error enabling RLS: {e}")
            
        try:
            supabase.postgrest.schema('public').execute(select_policy_query)
            print("Created select policy")
        except Exception as e:
            print(f"Error creating select policy: {e}")
            
        try:
            supabase.postgrest.schema('public').execute(insert_policy_query)
            print("Created insert policy")
        except Exception as e:
            print(f"Error creating insert policy: {e}")
            
        try:
            supabase.postgrest.schema('public').execute(update_policy_query)
            print("Created update policy")
        except Exception as e:
            print(f"Error creating update policy: {e}")
            
        try:
            supabase.postgrest.schema('public').execute(delete_policy_query)
            print("Created delete policy")
        except Exception as e:
            print(f"Error creating delete policy: {e}")
            
        return True
    except Exception as e:
        print(f"Error checking/fixing RLS policies: {e}")
        import traceback
        traceback.print_exc()
        return False

def get_resources():
    """
    Get all resources
    """
    try:
        response = supabase.table("resources") \
            .select("*") \
            .order("created_at") \
            .execute()
        return response.data if response.data else []
    except Exception as e:
        print(f"Error getting resources: {e}")
        return []

def get_organization_resources(organization=None):
    """
    Get resources filtered by organization
    
    If organization is None, returns all resources.
    Otherwise, returns resources created by users in the specified organization.
    """
    try:
        if not organization:
            # If no organization, just return all resources
            print("No organization specified, returning all resources")
            return get_resources()
        
        print(f"Getting resources for organization: {organization}")
        
        # First get users in the organization
        users_response = supabase.table("users") \
            .select("id, username, email, Organization") \
            .eq("Organization", organization) \
            .execute()
            
        print(f"Found {len(users_response.data) if users_response.data else 0} users in organization '{organization}'")
        
        if not users_response.data:
            print(f"No users found in organization: {organization}")
            return []
            
        # Extract user IDs and print details for debugging
        org_user_ids = []
        for user in users_response.data:
            org_user_ids.append(user["id"])
            print(f"User in org: {user.get('username')} ({user.get('email')}), Organization: {user.get('Organization')}")
        
        # Print the list of user IDs
        print(f"User IDs in organization: {org_user_ids}")
        
        # Now get resources created by these users
        if len(org_user_ids) == 1:
            # If there's only one user, use eq operator
            response = supabase.table("resources") \
                .select("*") \
                .eq("user_id", org_user_ids[0]) \
                .order("created_at") \
                .execute()
        else:
            # If there are multiple users, use in_ operator
            response = supabase.table("resources") \
                .select("*") \
                .in_("user_id", org_user_ids) \
                .order("created_at") \
                .execute()
            
        print(f"Found {len(response.data) if response.data else 0} resources for users in organization '{organization}'")
        
        if response.data:
            # Print details of resources for debugging
            for resource in response.data:
                print(f"Resource: {resource.get('text')[:30]}... | User ID: {resource.get('user_id')}")
        
        return response.data if response.data else []
    except Exception as e:
        print(f"Error getting organization resources: {e}")
        import traceback
        traceback.print_exc()
        return []

def add_resource(text, user_id=None):
    """
    Add a new resource
    """
    try:
        print(f"Adding resource with text: '{text}' and user_id: {user_id}")
        
        # Create data dictionary with text and created_at timestamp
        data = {
            "text": text,
            "created_at": datetime.datetime.now().isoformat()
        }
        
        # Add user_id if provided
        if user_id is not None:
            data["user_id"] = user_id
            
        print(f"Resource data being sent to database: {data}")
        
        response = supabase.table("resources") \
            .insert(data) \
            .execute()
            
        if response.data:
            print(f"Resource created successfully: {response.data[0]}")
            return response.data[0]
        else:
            print(f"No data returned from resource creation: {response}")
            return None
    except Exception as e:
        print(f"Error adding resource: {e}")
        import traceback
        traceback.print_exc()
        return None

def delete_resource(resource_id):
    """
    Delete a resource
    """
    try:
        supabase.table("resources") \
            .delete() \
            .eq("id", resource_id) \
            .execute()
        return True
    except Exception as e:
        print(f"Error deleting resource: {e}")
        return False

def update_resource(resource_id, text):
    """
    Update a resource
    """
    try:
        response = supabase.table("resources") \
            .update({"text": text}) \
            .eq("id", resource_id) \
            .execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error updating resource: {e}")
        return None 
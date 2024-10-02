import bcrypt
import json

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    #encrypts the plain text string using UTF-8 encoding for storage and security.

def username_exists(username):
    with open('users.json','r') as f:
        data = json.load(f)

    for user in data['users']:
        if user['username'] == username:
            return True
    return False

def save_user(username, password):
    try:
        if username_exists(username):
            print(f"Username '{username}' is already in use, please choose a different name.")
            return

        with open('users.json','r') as f:
            data = json.load(f)

        hashed_password = hash_password(password)

        data['users'].append({"username": username, "password": hashed_password.decode('utf-8')})

        with open('users.json', 'w') as f:
            json.dump(data, f , indent=4)

        print(f"User {username} has registered successfully!")

    except FileNotFoundError:
        print("Error: users.json not found.")
    except json.JSONDecodeError:
        print("Error: The .json file is corrupted.")
    except Exception as e:
        print(f"An unexpected error occured: {e}")



def check_login(username, password):
    with open('users.json','r') as f:
        data = json.load(f)

    for user in data['users']:
        if user['username'] == username:
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                print("Login successful!")
                return True
            else:
                print("Incorrect password, please try again.")
                return False
    print(f"Username '{username}' not found, please try again.")
    return False

def log_out():
    print("Logged out successfully.")


def delete_user(username):
    with open('users.json', 'r') as f:
        data = json.load(f)

    if not username_exists(username):
        print(f"Username '{username}' does not exist.")
        return

    password = input("Enter your password to proceed: ")

    if check_login(username, password):
        confirm_password = input("Please re-enter your password to delete your account: ")

        stored_hashpw = next((user['password'] for user in data['users'] if user['username'] == username), None)

        if stored_hashpw and bcrypt.checkpw(confirm_password.encode('utf-8'), stored_hashpw.encode('utf-8')):
            data['users'] = [user for user in data['users'] if user['username'] != username]

            with open('users.json', 'w') as f:
                json.dump(data, f, indent=4)

            print(f"User '{username}'was deleted.")

        else:
            print("Incorrect password. Deletion cancelled.")

    else:
        print("Incorrect password. Deletion cancelled.")

def main():
    while True:
        print("\n1. Register")
        print("2. Log In")
        print("3. Log Out")
        print("4. Delete User")
        print("5. Exit")

        choice = input("Select an option: ")

        if choice == '1':
            username = input("Enter a new username: ")
            password = input("Enter a new password: ")
            save_user(username, password)

        elif choice == '2':
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            if check_login(username, password):
                pass

        elif choice == '3':
            log_out()

        elif choice == '4':
            username = input("Enter the username you want to delete: ")
            delete_user(username)

        elif choice == '5':
            print("Bye for now.")
            break

        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    main()
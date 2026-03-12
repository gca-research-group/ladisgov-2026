##
# Programmer   : Regis Rodolfo Schuch
# Date         : 10 June 2024
#              : Applied Computing Research Group, Unijui University, Brazil
#              : regis.schuch@unijui.edu.br
#              :
# Title        : command-line-interface.py 
#              :
# Description  : The command-line-interface.py programme provides a command-line interface (CLI) for interacting with launcher.py which
#              : allows you to load, compile, list, delete and execute C files. command-line-interface.py is integrated with
#              : launcher.py, where the CLI sends HTTP requests to REST endpoints. This allows interaction between the CLI and the launcher
#              : to perform operations such as uploading, compiling and running programmes.
#              :
#              : Flow of Operation:
#              : 1) Imports and Configurations:
#              :  a) Imports the libraries needed for the CLI to work.
#              :  b) Defines the server URL and SSL settings. 
#              :  
#              : 2) CLI Definition:
#              :  a) Defines a group of commands using the Click library. 
#              : 
#              : 3) CLI commands:
#              :  a) list_files sends a GET request to the server to list all uploaded files.
#              :  b) click.echo prints messages to the user in the CLI.
#              :  c) requests.get: Makes a GET request to the /files endpoint defined in launcher.py.
#              :  d) upload sends a POST request to upload a file.
#              :  e) @click.argument sets the file_path argument to mandatory and validates that the file path exists.
#              :  f) requests.post makes a POST request to the /upload endpoint in launcher.py.
#              :  g) delete sends a DELETE request to delete a specific file.
#              :  h) requests.delete makes a DELETE request to the /files/{program_id} endpoint in launcher.py.
#              :  i) compile_program sends a POST request to compile a programme.
#              :  j) requests.post makes a POST request to the /compile/{program_id} endpoint in launcher.py.
#              :  k) execute_program_in_background runs a programme in the background.
#              :  l) subprocess.Popen runs a system process in the background.
#              :  m) execute sends a POST request to execute a programme.
#              :  n) threading.Thread creates a thread to run the programme in the background.
#              :
# Source       : Some inspiration from
#              : https://flask.palletsprojects.com/en/3.0.x/
#              : https://flask.palletsprojects.com/en/3.0.x/patterns/sqlite3/
#              : https://docs.python.org/3/howto/logging.html
#              : https://docs.python.org/3/howto/logging-cookbook.html
#              : https://stackoverflow.blog/2020/03/02/best-practices-for-rest-api-design/
#              : https://medium.com/@bubu.tripathy/best-practices-for-designing-rest-apis-5b1809545e3c    
#              : https://towardsdatascience.com/creating-restful-apis-using-flask-and-python-655bad51b24
#              : https://auth0.com/blog/developing-restful-apis-with-python-and-flask/    
#              : https://flask-restful.readthedocs.io/en/latest/
#              : https://medium.com/@geekprogrammer11/understanding-ssl-with-flask-api-d0b137906cbd
#              : https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https
#              : https://docs.python.org/3/library/subprocess.html
#              :
#              :
# Install      :
# dependencies : The launcher.py code was executed on the Unix-enabled CheriBSD Operating System, which extends 
#              : FreeBSD
#              : $ sudo pkg64 install python3
#              :
#              : $ sudo pkg64 install py39-pip
#              : 
#              : $ pip install click
#              :
# Compile and  :
# run          : $ python3 command-line-interface.py 
#              :
#              :
## 

import click
import requests
import subprocess
import urllib3
import os
import stat
import threading

# URL of the server running on Morello Board for local access
SERVER_URL = 'https://127.0.0.1:5000'
# Set to True if using a valid SSL certificate
VERIFY_SSL = False

# Disable warnings for insecure HTTP requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@click.group()
def cli():
    """CLI for the backend application."""
    pass

@cli.command(name='list-files')
def list_files():
    """List all uploaded files."""
    click.echo("Sending request to list files")
    response = requests.get(f"{SERVER_URL}/files", verify=VERIFY_SSL)
    if response.status_code == 200:
        click.echo("Request successful, listing files")
        files = response.json()
        for file in files:
            click.echo(f"{file['id']}: {file['file_name']} - {file['file_path']}")
            if file.get('executables'):
                for exe in file['executables']:
                    click.echo(f"    Executable: {exe}")
            if file.get('certificates'):
                for cert in file['certificates']:
                    click.echo(f"    Certificate: {cert}")
    else:
        click.echo(f"Error: {response.json().get('error')}")

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
def upload(file_path):
    """Upload a file."""
    with open(file_path, 'rb') as file:
        files = {'file': file}
        click.echo(f"Uploading file: {file_path}")
        response = requests.post(f"{SERVER_URL}/upload", files=files, verify=VERIFY_SSL)

    if response.status_code == 200:
        click.echo('File successfully uploaded')
    else:
        click.echo(f"Error: {response.json().get('error')}")

@cli.command()
@click.argument('program_id', type=int)
def delete(program_id):
    """Delete a selected program."""
    click.echo(f"Sending request to delete program ID {program_id}")
    response = requests.delete(f"{SERVER_URL}/files/{program_id}", verify=VERIFY_SSL)

    if response.status_code == 200:
        click.echo('Selected program deleted successfully')
    else:
        click.echo(f"Error: {response.json().get('error')}")

@cli.command(name='compile')
@click.argument('program_id', type=int)
def compile_program(program_id):
    """Compile and store a selected program."""
    click.echo(f"Sending request to compile program ID {program_id}")
    response = requests.post(f"{SERVER_URL}/compile/{program_id}", verify=VERIFY_SSL)

    if response.status_code == 200:
        click.echo('Compilation successful')
        output = response.json().get('output', '')
        error_output = response.json().get('error_output', '')
        if output:
            click.echo(f"Output:\n{output}")
        if error_output:
            click.echo(f"Error Output:\n{error_output}")
    else:
        click.echo(f"Error: {response.json().get('error')}")
        if response.json().get('output'):
            click.echo(f"Output:\n{response.json().get('output')}")

def execute_program_in_background(executable_path):
    """Execute the program in the background and capture output to log file."""
    log_file = f"{executable_path}.log"
    with open(log_file, 'w') as log:
        subprocess.Popen([executable_path], stdout=log, stderr=log, start_new_session=True, close_fds=True)

def execute_and_notify(program_id):
    """Execute a compiled program and notify upon completion."""
    click.echo(f"Sending request to execute program ID {program_id}")
    response = requests.post(f"{SERVER_URL}/execute/{program_id}", verify=VERIFY_SSL)
    click.echo(f"Received response status code: {response.status_code}")

    if response.status_code == 200:
        try:
            response_json = response.json()
            executable_path = response_json.get('executable_path')
            if executable_path:
                if not os.path.exists(executable_path):
                    click.echo(f"Error: Executable path '{executable_path}' does not exist.")
                    return

                # Ensure the executable has the correct permissions
                os.chmod(executable_path, stat.S_IRWXU)

                # Run the program in the background
                execute_program_in_background(executable_path)
                click.echo(f"Program is running in the background. Check log file '{executable_path}.log' for output.")
            else:
                click.echo("Executable path not provided.")
        except Exception as e:
            click.echo(f"Error processing response: {e}")
    else:
        click.echo(f"Error: {response.json().get('error')}")
        if response.json().get('output'):
            click.echo(f"Output:\n{response.json().get('output')}")

    click.echo("\nReturning to the menu...\n")
    print("\n", flush=True)

@cli.command()
@click.argument('program_id', type=int)
def execute(program_id):
    """Execute a compiled program."""
    # Start the background execution thread
    execution_background_thread = threading.Thread(target=execute_and_notify, args=(program_id,))
    execution_background_thread.start()

def get_valid_input(prompt, validation_func):
    """Get valid input from the user."""
    while True:
        user_input = input(prompt)
        try:
            return validation_func(user_input)
        except ValueError as e:
            click.echo(f"Error: {e}")

def run_menu():
    """Run the interactive menu."""
    while True:
        click.echo("\n|Menu:                  |")
        click.echo("-------------------------")
        click.echo("| 1. List files         |")
        click.echo("| 2. Upload a file      |")
        click.echo("| 3. Delete a program   |")
        click.echo("| 4. Compile a program  |")
        click.echo("| 5. Execute a program  |")
        click.echo("| 6. Exit               |")
        click.echo("-------------------------")
        choice = input("Choose an option: ")

        if choice == '1':
            list_files(standalone_mode=False)
        elif choice == '2':
            file_path = input("Enter the path of the file to upload: ")
            try:
                upload([file_path], standalone_mode=False)
            except click.BadParameter as e:
                click.echo(f"Error: {e}")
        elif choice == '3':
            program_id = get_valid_input("Enter the ID of the program to delete: ", int)
            delete([str(program_id)], standalone_mode=False)
        elif choice == '4':
            program_id = get_valid_input("Enter the ID of the program to compile: ", int)
            compile_program([str(program_id)], standalone_mode=False)
        elif choice == '5':
            program_id = get_valid_input("Enter the ID of the program to execute: ", int)
            execute([str(program_id)], standalone_mode=False)
        elif choice == '6':
            click.echo("Exiting...")
            break
        else:
            click.echo("Invalid option. Please try again.")

if __name__ == '__main__':
    run_menu()


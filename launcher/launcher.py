from flask import Flask, request, jsonify
import os
import json
import subprocess
import stat
import signal
import sys
import time

# Application settings
SOURCE_FOLDER = 'programs-data-base/sources'
CHERI_CAPS_EXECUTABLE_FOLDER = 'programs-data-base/cheri-caps-executables'
CERTIFICATE_FOLDER = 'programs-data-base/certificates'
ALLOWED_EXTENSIONS = {'c'}  # Only allow files with .c extension
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB file size limit
FILE_DATABASE = 'programs-data-base/file_database.json'

# Initialize the Flask application
app = Flask(__name__)
app.config['SOURCE_FOLDER'] = SOURCE_FOLDER
app.config['CHERI_CAPS_EXECUTABLE_FOLDER'] = CHERI_CAPS_EXECUTABLE_FOLDER
app.config['CERTIFICATE_FOLDER'] = CERTIFICATE_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# In-memory file database
file_db = {}

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_file_database():
    """Load the file database from the JSON file."""
    global file_db
    if os.path.exists(FILE_DATABASE):
        try:
            with open(FILE_DATABASE, 'r') as db_file:
                file_db = json.load(db_file)
            # Verify existence of files and executables
            for program_id, file_info in list(file_db.items()):
                if not os.path.exists(file_info['file_path']) or (file_info['executables'] and not all(os.path.exists(exe) for exe in file_info['executables'])):
                    del file_db[program_id]
            save_file_database()
        except json.JSONDecodeError:
            print(f"Error: JSON file {FILE_DATABASE} is corrupted. Recreating the file.")
            file_db = {}
            save_file_database()
    else:
        file_db = {}

def save_file_database():
    """Save the file database to the JSON file."""
    with open(FILE_DATABASE, 'w') as db_file:
        json.dump(file_db, db_file)

def handle_exit_signal(signum, frame):
    """Handle exit signals to save the database."""
    save_file_database()
    sys.exit(0)

# Register signal handlers to save the database on exit
signal.signal(signal.SIGINT, handle_exit_signal)
signal.signal(signal.SIGTERM, handle_exit_signal)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Endpoint to upload a file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = os.path.basename(file.filename)
        secure_filename = os.path.join(app.config['SOURCE_FOLDER'], filename)

        # Check file size
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0, os.SEEK_SET)

        if file_length > app.config['MAX_CONTENT_LENGTH']:
            return jsonify({'error': 'File too large'}), 400

        os.makedirs(app.config['SOURCE_FOLDER'], exist_ok=True)
        file.save(secure_filename)

        # Insert file information into the in-memory database
        program_id = len(file_db) + 1
        file_db[program_id] = {'file_name': filename, 'file_path': secure_filename, 'executables': [], 'certificates': []}
        save_file_database()

        return jsonify({'message': 'File successfully uploaded'}), 200

    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/files', methods=['GET'])
def list_files():
    """Endpoint to list all uploaded files."""
    files_list = [
        {
            'id': file_id, 
            'file_name': file_info['file_name'], 
            'file_path': file_info['file_path'], 
            'executables': file_info.get('executables', []),
            'certificates': [os.path.join(cert, "certificate.pem") for cert in file_info.get('certificates', [])]
        } 
        for file_id, file_info in file_db.items()
    ]
    return jsonify(files_list), 200

@app.route('/files/<int:program_id>', methods=['DELETE'])
def delete_file(program_id):
    """Endpoint to delete a specific file."""
    app.logger.debug(f"Delete request received for program ID: {program_id}")

    if program_id not in file_db:
        app.logger.error(f"File not found for program ID: {program_id}")
        return jsonify({'error': 'File not found'}), 404

    file_info = file_db.pop(program_id)
    save_file_database()

    app.logger.debug(f"File info to be deleted: {file_info}")

    if os.path.exists(file_info['file_path']):
        os.remove(file_info['file_path'])
    else:
        app.logger.warning(f"File path does not exist: {file_info['file_path']}")

    for executable_path in file_info.get('executables', []):
        if executable_path and os.path.exists(executable_path):
            os.remove(executable_path)
        else:
            app.logger.warning(f"Executable path does not exist: {executable_path}")

    for certificate_path in file_info.get('certificates', []):
        certificate_dir = os.path.join(app.config['CERTIFICATE_FOLDER'], certificate_path)
        if os.path.exists(certificate_dir):
            for file_name in os.listdir(certificate_dir):
                file_path = os.path.join(certificate_dir, file_name)
                if os.path.exists(file_path):
                    os.remove(file_path)
            os.rmdir(certificate_dir)
        else:
            app.logger.warning(f"Certificate path does not exist: {certificate_dir}")

    app.logger.info(f"File successfully deleted for program ID: {program_id}")
    return jsonify({'message': 'File successfully deleted'}), 200

@app.route('/compile/<int:program_id>', methods=['POST'])
def compile_program(program_id):
    """Endpoint to compile a specific program."""
    if program_id not in file_db:
        return jsonify({'error': 'Invalid program selected'}), 404

    file_info = file_db[program_id]
    file_path = file_info['file_path']
    if not os.path.exists(file_path):
        return jsonify({'error': 'File does not exist'}), 404

    # Generate a unique name for the executable
    timestamp = int(time.time())
    executable_name = f"{os.path.splitext(os.path.basename(file_path))[0]}_{timestamp}"
    executable_path = os.path.join(app.config['CHERI_CAPS_EXECUTABLE_FOLDER'], executable_name)

    compile_command = f"clang-morello -march=morello+c64 -mabi=purecap -g -o {executable_path} {file_path} -L. -Wl,-dynamic-linker,/libexec/ld-elf-c18n.so.1 -lssl -lcrypto -lpthread"
    try:
        result = subprocess.run(compile_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        error_output = result.stderr.decode('utf-8')

        # Log compilation output
        app.logger.info(f"Compilation output for program ID {program_id}:\n{output}")
        if error_output:
            app.logger.error(f"Compilation error output for program ID {program_id}:\n{error_output}")

        # Prepare certificate directory
        cert_dir = os.path.join(app.config['CERTIFICATE_FOLDER'], executable_name)
        os.makedirs(cert_dir, exist_ok=True)

        # Store the executable path and certificate directory in the in-memory database
        file_info['executables'].append(executable_path)
        file_info['certificates'].append(cert_dir)
        save_file_database()

        return jsonify({'message': 'Compilation successful', 'output': output, 'error_output': error_output, 'executable_path': executable_path, 'certificate_path': cert_dir}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Compilation failed for program ID {program_id}: {e}")
        error_output = e.output.decode('utf-8') if e.output else "No output"
        return jsonify({'error': f'Compilation failed: {e}', 'output': error_output}), 500

@app.route('/execute/<int:program_id>', methods=['POST'])
def execute_program(program_id):
    """Endpoint to execute a compiled program."""
    if program_id not in file_db:
        return jsonify({'error': 'Invalid program selected'}), 404

    executable_paths = file_db[program_id].get('executables', [])
    if not executable_paths:
        return jsonify({'error': 'Executable does not exist. Please compile the program first.'}), 404

    executable_path = executable_paths[-1]  # Use the last compiled executable
    if not os.path.exists(executable_path):
        return jsonify({'error': 'Executable does not exist. Please compile the program first.'}), 404

    # Set execution permissions for the file
    os.chmod(executable_path, stat.S_IRWXU)

    # Execute the program using the specified command
    execute_command = f"env LD_C18N_LIBRARY_PATH=. {executable_path}"
    try:
        result = subprocess.run(execute_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        error_output = result.stderr.decode('utf-8')

        # Log execution output
        app.logger.info(f"Execution output for program ID {program_id}:\n{output}")
        if error_output:
            app.logger.error(f"Execution error output for program ID {program_id}:\n{error_output}")

        return jsonify({'message': 'Execution successful', 'output': output, 'error_output': error_output, 'executable_path': executable_path}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Execution failed for program ID {program_id}: {e}")
        error_output = e.output.decode('utf-8') if e.output else "No output"
        return jsonify({'error': f'Execution failed: {e}', 'output': error_output}), 500

if __name__ == '__main__':
    os.makedirs(SOURCE_FOLDER, exist_ok=True)
    os.makedirs(CHERI_CAPS_EXECUTABLE_FOLDER, exist_ok=True)
    os.makedirs(CERTIFICATE_FOLDER, exist_ok=True)
    os.makedirs(os.path.dirname(FILE_DATABASE), exist_ok=True)
    load_file_database()
    # Start the Flask server with HTTPS
    app.run(debug=True, ssl_context=('keys/cert.pem', 'keys/prk.pem'), host='127.0.0.1', port=5000)

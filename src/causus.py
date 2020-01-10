import hashlib
import os
import platform
import subprocess
import sys
import time

from clint.textui import progress
from lxml import html
import requests

#######################################
#						Global variables					#
#######################################
# TODO: Determine the installation location and cli tool for other platforms
VIPRE_CLI_PATHS_FOR_PLATFORM = {
	"Linux": "",
	"Darwin": "",
	"Windows": "C:/Program Files (x86)/VIPRE/SBAMCommandLineScanner.exe"
}
# This needs to point to the SBAMCommandLineScanner 
# executable/binary in the VIPRE installation directory.
# If this cannot be determined, the script will exit immediately
VIPRE_CLI_BIN = None

# The page which hosts the lastest vipre definitions for manual download
DEFINITIONS_UPDATE_URL = "http://definitions.vipreantivirus.com"

# The current user's home directory. The user running this script should have access to this directory
USER_HOME = os.path.expanduser("~")
# This will serve as the scripts workspace.
SCRIPT_WORKSPACE = os.path.join(USER_HOME, ".vipre_updater")
# Definitions will be downloaded to a subdirectory in the script's workspace
DEFINITIONS_PATH = os.path.join(SCRIPT_WORKSPACE, "defs")

# This will be updated to be the current definitions file once determined
DEFINITIONS_SGNX_FILE = "replaced_at_runtime.sgnx"
# Actions and errors produced by the script will be logged to this file
LOG_FILE = os.path.join(SCRIPT_WORKSPACE, "log.txt")
LOG_FILE_HANDLE = None
#######################################

def main():
	success = False
	global LOG_FILE_HANDLE
	with open(LOG_FILE, 'w') as LOG_FILE_HANDLE:
		# Route stdout and stderr to the log file
		sys.stdout = LOG_FILE_HANDLE
		sys.stderr = LOG_FILE_HANDLE

		log("Starting VIPRE threat definitions update.")
		# Determine the user's platform system os, and fetch the appropriate cli executable/bin.
		# If it cannot be determined, the script will exit immediately.
		global VIPRE_CLI_BIN
		VIPRE_CLI_BIN = determine_vipre_cli_directory()

		# Set up the script's workspace environment if needed.
		setup_workspace()
		# Scrape the download link, version, and md5 checksum for the most recent entry from the vipre definitions webpage.
		definitions_url, version, md5_checksum = scrape_latest_definitions()
		# Read the installed definitions version.
		current_defs_version = get_installed_definitions_version()
		# If the last definitions version matches the scraped one, definitions are current and there's nothing to do.
		if current_defs_version == version:
			log("Definitions are current.")
			exit(0)
		
		# Set the definitions file to the definitions directory in the workspace + definitions file name.
		global DEFINITIONS_SGNX_FILE
		DEFINITIONS_SGNX_FILE = os.path.join(DEFINITIONS_PATH, definitions_url[definitions_url.rfind('/')+1:])
		# Just one more check. If the definitions file is already located in the definitions directory in the workspace,
		# calculate the md5 checksum of the file against the md5 value that was scraped. If the checksum matches the file is good.
		if os.path.isfile(DEFINITIONS_SGNX_FILE) == True and verify_definitions_file_checksum(md5_checksum):
			# Initialize success to True; everything is good so far.
			success = True
			log("Latest definition already downloaded.")
		# Otherwise, if the file is there but the checksum doesn't match, its possible the script was inturrupted while downloading
		# the file, or internet connection was lost, user placed a non-recent file, etc...
		else:
			# Try re-downloading the definitions file again.
			download_definitions(definitions_url)
			# Re-verify the md5 checksum for the downloaded file.
			success = verify_definitions_file_checksum(md5_checksum)
			# Sleep to allow the os to close/release the file after reading it.
			if success == True: time.sleep(3)

		# Only if success is still true (verify_definitions_file_checksum has returned True) apply the definitions using the vipre cli executable.
		success = success and apply_definitions()
		# Sleep to allow the os to close/release the file after applying it.
		if success == True: time.sleep(3)
		# Only if success is still true (apply_definitions has returned True) perform cleanup of workspace.
		success = success and cleanup_workspace()
		log("Done!")

##
# Performs a request to the vipre definitions url page to scrape the latest definitions file download link,
# version, and md5 checksum of the file.
##
def scrape_latest_definitions()->tuple:
	log("Obtaining latest definitions from: " + DEFINITIONS_UPDATE_URL)
	raw_html = requests.get(DEFINITIONS_UPDATE_URL).content
	raw_html = str(raw_html).replace(r"\r","").replace(r"\n","").replace(r"\t","")
	dom = html.fromstring(raw_html)
	tables = dom.findall('.//table')
	latest = tables[0].findall('.//tr')[1]
	cells = latest.findall('.//td')
	link = cells[0].find('.//a').get('href')
	version = cells[1].text_content().strip()
	md5 = cells[4].text_content().strip().upper()
	log(f"Found latest definitions: {version} - {link}")
	return (link, version, md5)

##
# Performs the download of the provided definitions file url to
# the <SCRIPT_WORKSPACE>/defs directory
##
def download_definitions(url:str):
	log("Starting definitions download...")
	req = requests.get(url,stream=True)
	with open(DEFINITIONS_SGNX_FILE,'wb') as definitions_file:
		content_length = int(req.headers.get('content-length'))
		for chunk in progress.bar(req.iter_content(chunk_size=1024), expected_size=(content_length/1024) + 1):
			if chunk:
				definitions_file.write(chunk)
				definitions_file.flush()
	log("Download complete.")

##
# Applies the locally downloaded definitions file using the identified vipre cli executable/binary from the current installation
##
def apply_definitions()->bool:
	# Run subprocess using vipre cli to apply the downloaded definitions, capturing the output in stdout and stderr
	result = subprocess.run([VIPRE_CLI_BIN, "/applydefs", DEFINITIONS_SGNX_FILE], capture_output=True, encoding="utf-8")
	if result.stdout is not None:
		log(result.stdout)
	if result.stderr is not None:
		log(result.stderr)
	if result.returncode == 0:
		log("Definitions applied successfully!")
		return True
	else:
		log("Failed to apply latest definitions file!")
		return False

##
#
##
def get_installed_definitions_version()->str:
	result = subprocess.run([VIPRE_CLI_BIN, "/displaylocaldefversion"], capture_output=True, encoding="utf-8").stdout
	version = result.split(" - ")[0]
	return version

##
# Verifies the provided checksum value against the calculated md5 checksum of the downloaded definitions file. If these values match
# returns True, otherwise returns False
##
def verify_definitions_file_checksum(md5:str)->bool:
	log("Verifying checksum...")
	buff_size = 65536
	hasher = hashlib.md5()
	with open(DEFINITIONS_SGNX_FILE, 'rb') as definitions_file:
		buf = definitions_file.read(buff_size)
		while len(buf) > 0:
			hasher.update(buf)
			buf = definitions_file.read(buff_size)
	checksum = hasher.hexdigest().upper()
	if checksum == md5:
		log("Checksum verified.")
		return True
	else:
		log(f"Checksum {checksum} does not match {md5}")
		return False

##
# Sets up the this script's workspace environment, which is used for downloaded definitions files, logs, etc..
##
def setup_workspace():
	if os.path.exists(SCRIPT_WORKSPACE) == False:
		os.makedirs(SCRIPT_WORKSPACE, mode=0o777)
	if os.path.exists(DEFINITIONS_PATH) == False:
		os.makedirs(DEFINITIONS_PATH, mode=0o777)

##
# Cleans up the script's workspace environment, which includes deleting the downloaded definitions file (to prevent taking up unnecessary space).
##
def cleanup_workspace()->bool:
	log("Cleaning up definitions file...")
	return os.remove(DEFINITIONS_SGNX_FILE)

##
# Determines the location of the vipre cli executable/binary used for applying definitions updates
# based on the current system platform os.
# If the platform cannot be determined, the script will exit with a non-zero value.
##
def determine_vipre_cli_directory()->str:
	global VIPRE_CLI_PATHS_FOR_PLATFORM
	cli_path = VIPRE_CLI_PATHS_FOR_PLATFORM[platform.system()]
	if cli_path is None:
		log("Unable to determine platform system os or vipre is installed in a non-default directory.")
		exit(-1)
	elif cli_path == "":
		log("The current platform system os is not yet supported.")
		exit(-1)
	else:
		return cli_path

##
# Accepts a message and prints it to the console (also writing to log file), prepending the current date/time.
##
def log(message:str):
	now = time.strftime("%Y-%d-%m %H:%M:%S", time.localtime())
	print(f"[{now}] {message}")

# Call main() to kick everything off.
main()
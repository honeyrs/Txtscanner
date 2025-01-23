import time
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext

# Your Bot's API key
API_KEY = "8152265435:AAH9ex75KOmXl6lb_M79EAQgUvnPjbfkYUA"
# VirusTotal API key (you need to sign up on VirusTotal for a free key)
VIRUSTOTAL_API_KEY = "f8c0a52b07f142927c575dee61a7ec981bdc5e4ed88d17d123aaa0c56ae0b529"

# Function to check a file with VirusTotal
def scan_file(file_path: str):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    # Upload the file to VirusTotal for scanning
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(url, headers=headers, files=files)
    
    # Parse the result
    if response.status_code == 200:
        json_response = response.json()
        if 'data' in json_response:
            return json_response['data']
        else:
            return None
    else:
        return None

# Command to handle '/txt' command (send file in parts with delay)
def txt_command(update: Update, context: CallbackContext):
    chat_id = update.message.chat_id
    message = "Please upload a .txt file for scanning."
    context.bot.send_message(chat_id, message)

# Function to handle incoming file uploads
def handle_file(update: Update, context: CallbackContext):
    file = update.message.document
    file_name = file.file_name
    if file_name.endswith('.txt'):
        # Download the file
        file_id = file.file_id
        new_file = context.bot.get_file(file_id)
        file_path = f"./{file_name}"
        new_file.download(file_path)
        
        # Scan the file for viruses
        scan_result = scan_file(file_path)
        
        if scan_result:
            # Send the result of the scan
            result_message = "File scan complete. Here are the results:\n"
            result_message += str(scan_result)
            context.bot.send_message(update.message.chat_id, result_message)
            
            # If it's a .txt file, send content with delay
            with open(file_path, "r") as txt_file:
                content = txt_file.readlines()
                for line in content:
                    context.bot.send_message(update.message.chat_id, line.strip())
                    time.sleep(5)  # Delay of 5 seconds between messages
        else:
            context.bot.send_message(update.message.chat_id, "File scanning failed.")
    else:
        context.bot.send_message(update.message.chat_id, "Please upload a valid .txt file.")

# Function to start the bot
def start(update: Update, context: CallbackContext):
    update.message.reply_text('Hello! Send me a .txt file and I will scan it for viruses.')

async def main():
    # Create an Application object (use Application instead of Updater in v20+)
    application = Application.builder().token(API_KEY).build()

    # Add command handler for /start and /txt
    application.add_handler(CommandHandler('start', start))
    application.add_handler(CommandHandler('txt', txt_command))

    # Add message handler for handling file uploads
    application.add_handler(MessageHandler(filters.Document.MimeType("text/plain"), handle_file))

    # Start the bot
    await application.run_polling()

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())

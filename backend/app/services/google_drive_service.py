from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import os

class GoogleDriveService:
    def __init__(self):
        self.creds = None
        self.client_config = {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        }
        self.SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

    def is_connected(self):
        return self.creds and self.creds.valid

    def get_authorization_url(self):
        flow = Flow.from_client_config(self.client_config, self.SCOPES)
        flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
        authorization_url, _ = flow.authorization_url(prompt='consent')
        return authorization_url

    def exchange_code(self, code):
        flow = Flow.from_client_config(self.client_config, self.SCOPES)
        flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
        flow.fetch_token(code=code)
        self.creds = flow.credentials

    def list_files(self):
        service = build('drive', 'v3', credentials=self.creds)
        results = service.files().list(pageSize=10, fields="nextPageToken, files(id, name)").execute()
        return results.get('files', [])

    def get_file_content(self, file_id):
        service = build('drive', 'v3', credentials=self.creds)
        file = service.files().get(fileId=file_id, alt='media').execute()
        return file.decode('utf-8')

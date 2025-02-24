from supabase import create_client, Client
import os

class SupabaseService:
    def __init__(self):
        self.supabase: Client = create_client(
            os.getenv("SUPABASE_URL"),
            os.getenv("SUPABASE_KEY")
        )

    def list_tables(self):
        response = self.supabase.table('information_schema.tables').select('table_name').execute()
        return [table['table_name'] for table in response.data]

    def store_vector(self, table_name: str, file_path: str, vector: list):
        self.supabase.table(table_name).insert({
            "file_path": file_path,
            "vector": vector
        }).execute()

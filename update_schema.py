from app import app, db, User
import sqlalchemy as sa
from sqlalchemy.engine import reflection

def add_column_if_not_exists(table_name, column):
    """Add a column to a table if it doesn't exist already."""
    # Get the column name and type
    column_name = column.name
    column_type = column.type
    
    # Check if the column exists
    insp = reflection.Inspector.from_engine(db.engine)
    columns = [c['name'] for c in insp.get_columns(table_name)]
    
    if column_name not in columns:
        sql = f'ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}'
        print(f"Adding column {column_name} to {table_name}")
        with db.engine.connect() as conn:
            conn.execute(sa.text(sql))
            conn.commit()
    else:
        print(f"Column {column_name} already exists in {table_name}")

def update_schema():
    print("Checking if schema update is needed...")
    with app.app_context():
        try:
            # Get the columns we need to add
            columns_to_add = [
                sa.Column('google_id', sa.String(100), unique=True, nullable=True),
                sa.Column('apple_id', sa.String(100), unique=True, nullable=True),
                sa.Column('is_social_account', sa.Boolean(), default=False)
            ]
            
            for column in columns_to_add:
                add_column_if_not_exists('user', column)
                
            print("Schema update completed successfully.")
        except Exception as e:
            print(f"Error during schema update: {e}")

if __name__ == "__main__":
    update_schema() 
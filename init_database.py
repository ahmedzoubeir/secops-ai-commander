import asyncio
from database.models import Base, DATABASE_URL
from sqlalchemy.ext.asyncio import create_async_engine

async def init_db():
    engine = create_async_engine(DATABASE_URL, echo=True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        print("✅ Database tables created successfully!")

    await engine.dispose()

from database.models import init_db

if __name__ == "__main__":
    print("🚀 Initializing SecOps AI Database...")
    init_db()

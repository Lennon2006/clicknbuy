import logging
from logging.config import fileConfig

from flask import current_app
from alembic import context

# Alembic Config object, provides access to .ini config values
config = context.config

# Setup Python logging from config file (alembic.ini)
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')

def get_engine():
    """
    Get the SQLAlchemy engine from Flask-Migrate extension,
    compatible with Flask-SQLAlchemy v2 and v3+.
    """
    try:
        # For Flask-SQLAlchemy < 3
        return current_app.extensions['migrate'].db.get_engine()
    except (TypeError, AttributeError):
        # For Flask-SQLAlchemy >= 3
        return current_app.extensions['migrate'].db.engine

def get_engine_url():
    """
    Get database URL as a string, escaping % for Alembic config compatibility.
    """
    try:
        return get_engine().url.render_as_string(hide_password=False).replace('%', '%%')
    except AttributeError:
        return str(get_engine().url).replace('%', '%%')

# Set the sqlalchemy.url in alembic config dynamically
config.set_main_option('sqlalchemy.url', get_engine_url())

# Access the SQLAlchemy db instance from Flask-Migrate
target_db = current_app.extensions['migrate'].db

def get_metadata():
    """
    Retrieve MetaData object for autogenerate support.
    Flask-SQLAlchemy v3 uses 'metadatas' dict, older versions use 'metadata' attribute.
    """
    if hasattr(target_db, 'metadatas'):
        return target_db.metadatas[None]
    return target_db.metadata

def run_migrations_offline():
    """Run migrations without DB connection, using URL only."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=get_metadata(),
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations using a live DB connection."""
    def process_revision_directives(context, revision, directives):
        """
        Avoid creating empty migration scripts when no schema changes detected.
        """
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info('No changes in schema detected.')

    conf_args = current_app.extensions['migrate'].configure_args

    if conf_args.get("process_revision_directives") is None:
        conf_args["process_revision_directives"] = process_revision_directives

    connectable = get_engine()
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=get_metadata(),
            **conf_args
        )
        with context.begin_transaction():
            context.run_migrations()

# Entry point: offline or online mode
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

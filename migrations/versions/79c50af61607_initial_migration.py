"""initial migration

Revision ID: 79c50af61607
Revises: 
Create Date: 2024-07-14 12:49:14.744619

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '79c50af61607'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('yachts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('image_url', sa.String(length=255), nullable=True))

    # Update existing data if necessary
    op.execute("UPDATE yachts SET image_url='default_image_url' WHERE image_url IS NULL")

    # Modify column to be non-nullable
    with op.batch_alter_table('yachts', schema=None) as batch_op:
        batch_op.alter_column('image_url', nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('yachts', schema=None) as batch_op:
        batch_op.drop_column('image_url')

    # ### end Alembic commands ###

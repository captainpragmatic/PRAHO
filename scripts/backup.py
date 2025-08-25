#!/usr/bin/env python3
"""
PRAHO PLATFORM - Database Backup Script
===============================================================================
Automated backup system for Romanian hosting provider data
"""

import gzip
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import boto3
import django
from botocore.exceptions import ClientError

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.prod')
django.setup()

from django.conf import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pragmatichost/backup.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class PragmaticHostBackup:
    """
    Romanian hosting provider backup system
    
    Features:
    - Database backup (PostgreSQL/SQLite)
    - Media files backup
    - Configuration backup
    - S3 storage integration
    - Retention policy management
    - Email notifications
    """

    def __init__(self, backup_dir: str = '/backups/pragmatichost'):
        """
        Initialize backup system
        
        Args:
            backup_dir: Local backup directory
        """
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Backup retention (keep backups for 30 days)
        self.retention_days = 30

        # S3 configuration (if available)
        self.s3_enabled = all([
            hasattr(settings, 'AWS_ACCESS_KEY_ID'),
            hasattr(settings, 'AWS_SECRET_ACCESS_KEY'),
            hasattr(settings, 'AWS_STORAGE_BUCKET_NAME')
        ])

        if self.s3_enabled:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=getattr(settings, 'AWS_S3_REGION_NAME', 'eu-west-1')
            )
            self.s3_bucket = settings.AWS_STORAGE_BUCKET_NAME

        logger.info(f"Initialized PragmaticHost backup system (S3: {self.s3_enabled})")

    def create_full_backup(self) -> bool:
        """
        Create a complete backup of the system
        
        Returns:
            True if backup was successful
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"pragmatichost_backup_{timestamp}"
        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(exist_ok=True)

        try:
            logger.info(f"Starting full backup: {backup_name}")

            # 1. Database backup
            db_success = self._backup_database(backup_path)
            if not db_success:
                return False

            # 2. Media files backup
            media_success = self._backup_media_files(backup_path)
            if not media_success:
                return False

            # 3. Configuration backup
            config_success = self._backup_configuration(backup_path)
            if not config_success:
                return False

            # 4. Create compressed archive
            archive_path = self._create_archive(backup_path, backup_name)
            if not archive_path:
                return False

            # 5. Upload to S3 (if enabled)
            if self.s3_enabled:
                s3_success = self._upload_to_s3(archive_path, backup_name)
                if not s3_success:
                    logger.warning("S3 upload failed, but local backup is available")

            # 6. Cleanup old backups
            self._cleanup_old_backups()

            # 7. Remove temporary backup directory
            shutil.rmtree(backup_path)

            logger.info(f"Full backup completed successfully: {archive_path}")
            self._send_backup_notification(True, backup_name, str(archive_path))

            return True

        except Exception as e:
            logger.error(f"Full backup failed: {e}")
            self._send_backup_notification(False, backup_name, str(e))
            return False

    def _backup_database(self, backup_path: Path) -> bool:
        """Backup the database"""
        try:
            logger.info("Backing up database...")

            db_config = settings.DATABASES['default']
            db_backup_path = backup_path / 'database'
            db_backup_path.mkdir(exist_ok=True)

            if db_config['ENGINE'] == 'django.db.backends.postgresql':
                # PostgreSQL backup
                dump_file = db_backup_path / 'pragmatichost.sql'

                cmd = [
                    'pg_dump',
                    f"--host={db_config['HOST']}",
                    f"--port={db_config['PORT']}",
                    f"--username={db_config['USER']}",
                    f"--dbname={db_config['NAME']}",
                    '--no-password',
                    '--verbose',
                    '--format=custom',
                    f"--file={dump_file}"
                ]

                env = os.environ.copy()
                env['PGPASSWORD'] = db_config['PASSWORD']

                result = subprocess.run(cmd, check=False, env=env, capture_output=True, text=True)

                if result.returncode != 0:
                    logger.error(f"PostgreSQL backup failed: {result.stderr}")
                    return False

                # Compress the dump
                with open(dump_file, 'rb') as f_in:
                    with gzip.open(f"{dump_file}.gz", 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)

                dump_file.unlink()  # Remove uncompressed file

            elif db_config['ENGINE'] == 'django.db.backends.sqlite3':
                # SQLite backup
                db_file = Path(db_config['NAME'])
                if db_file.exists():
                    backup_file = db_backup_path / 'db.sqlite3'
                    shutil.copy2(db_file, backup_file)

                    # Compress the database
                    with open(backup_file, 'rb') as f_in:
                        with gzip.open(f"{backup_file}.gz", 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)

                    backup_file.unlink()  # Remove uncompressed file
                else:
                    logger.error("SQLite database file not found")
                    return False

            else:
                logger.error(f"Unsupported database engine: {db_config['ENGINE']}")
                return False

            logger.info("Database backup completed")
            return True

        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            return False

    def _backup_media_files(self, backup_path: Path) -> bool:
        """Backup media files"""
        try:
            logger.info("Backing up media files...")

            media_root = Path(settings.MEDIA_ROOT)
            if not media_root.exists():
                logger.info("No media files to backup")
                return True

            media_backup_path = backup_path / 'media'

            # Use rsync for efficient copying
            cmd = [
                'rsync',
                '-av',
                '--progress',
                f"{media_root}/",
                f"{media_backup_path}/"
            ]

            result = subprocess.run(cmd, check=False, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Media backup failed: {result.stderr}")
                return False

            logger.info("Media files backup completed")
            return True

        except Exception as e:
            logger.error(f"Media backup failed: {e}")
            return False

    def _backup_configuration(self, backup_path: Path) -> bool:
        """Backup configuration files"""
        try:
            logger.info("Backing up configuration...")

            config_backup_path = backup_path / 'config'
            config_backup_path.mkdir(exist_ok=True)

            # Configuration files to backup
            config_files = [
                '.env',
                'docker-compose.yml',
                'Dockerfile',
                'pyproject.toml',
                'requirements/',
                'config/settings/',
            ]

            project_root = Path(settings.BASE_DIR).parent

            for config_file in config_files:
                source = project_root / config_file
                if source.exists():
                    if source.is_file():
                        shutil.copy2(source, config_backup_path)
                    else:
                        dest = config_backup_path / source.name
                        shutil.copytree(source, dest, dirs_exist_ok=True)

            logger.info("Configuration backup completed")
            return True

        except Exception as e:
            logger.error(f"Configuration backup failed: {e}")
            return False

    def _create_archive(self, backup_path: Path, backup_name: str) -> Path | None:
        """Create compressed archive of backup"""
        try:
            logger.info("Creating backup archive...")

            archive_path = self.backup_dir / f"{backup_name}.tar.gz"

            cmd = [
                'tar',
                '-czf',
                str(archive_path),
                '-C',
                str(backup_path.parent),
                backup_path.name
            ]

            result = subprocess.run(cmd, check=False, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Archive creation failed: {result.stderr}")
                return None

            logger.info(f"Archive created: {archive_path}")
            return archive_path

        except Exception as e:
            logger.error(f"Archive creation failed: {e}")
            return None

    def _upload_to_s3(self, archive_path: Path, backup_name: str) -> bool:
        """Upload backup to S3"""
        try:
            logger.info("Uploading backup to S3...")

            s3_key = f"backups/pragmatichost/{backup_name}.tar.gz"

            self.s3_client.upload_file(
                str(archive_path),
                self.s3_bucket,
                s3_key,
                ExtraArgs={
                    'StorageClass': 'STANDARD_IA',  # Cheaper storage for backups
                    'ServerSideEncryption': 'AES256'
                }
            )

            logger.info(f"Backup uploaded to S3: s3://{self.s3_bucket}/{s3_key}")
            return True

        except ClientError as e:
            logger.error(f"S3 upload failed: {e}")
            return False

    def _cleanup_old_backups(self):
        """Remove old backup files"""
        try:
            logger.info("Cleaning up old backups...")

            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            deleted_count = 0

            # Cleanup local backups
            for backup_file in self.backup_dir.glob('pragmatichost_backup_*.tar.gz'):
                if backup_file.stat().st_mtime < cutoff_date.timestamp():
                    backup_file.unlink()
                    deleted_count += 1

            # Cleanup S3 backups (if enabled)
            if self.s3_enabled:
                try:
                    response = self.s3_client.list_objects_v2(
                        Bucket=self.s3_bucket,
                        Prefix='backups/pragmatichost/'
                    )

                    for obj in response.get('Contents', []):
                        if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                            self.s3_client.delete_object(
                                Bucket=self.s3_bucket,
                                Key=obj['Key']
                            )
                            deleted_count += 1

                except ClientError as e:
                    logger.warning(f"S3 cleanup failed: {e}")

            logger.info(f"Cleaned up {deleted_count} old backup files")

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    def _send_backup_notification(self, success: bool, backup_name: str, details: str):
        """Send backup notification email"""
        try:
            from django.core.mail import mail_admins

            if success:
                subject = f"PragmaticHost: Backup Successful - {backup_name}"
                message = f"Backup completed successfully.\n\nDetails: {details}"
            else:
                subject = f"PragmaticHost: Backup FAILED - {backup_name}"
                message = f"Backup failed!\n\nError: {details}"

            mail_admins(subject, message, fail_silently=True)

        except Exception as e:
            logger.error(f"Failed to send backup notification: {e}")

    def restore_backup(self, backup_file: str) -> bool:
        """
        Restore from a backup file
        
        Args:
            backup_file: Path to backup archive
            
        Returns:
            True if restore was successful
        """
        try:
            logger.info(f"Starting restore from: {backup_file}")

            # TODO: Implement restore functionality
            # This would involve:
            # 1. Extract backup archive
            # 2. Stop application
            # 3. Restore database
            # 4. Restore media files
            # 5. Restore configuration
            # 6. Restart application

            logger.warning("Restore functionality not yet implemented")
            return False

        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

    def list_backups(self) -> list[dict]:
        """List available backups"""
        backups = []

        # Local backups
        for backup_file in self.backup_dir.glob('pragmatichost_backup_*.tar.gz'):
            stat = backup_file.stat()
            backups.append({
                'name': backup_file.name,
                'path': str(backup_file),
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_mtime),
                'location': 'local'
            })

        # S3 backups (if enabled)
        if self.s3_enabled:
            try:
                response = self.s3_client.list_objects_v2(
                    Bucket=self.s3_bucket,
                    Prefix='backups/pragmatichost/'
                )

                # ⚡ PERFORMANCE: Use list extend for better performance than multiple appends
                backups.extend([
                    {
                        'name': obj['Key'].split('/')[-1],
                        'path': f"s3://{self.s3_bucket}/{obj['Key']}",
                        'size': obj['Size'],
                        'created': obj['LastModified'].replace(tzinfo=None),
                        'location': 's3'
                    }
                    for obj in response.get('Contents', [])
                ])

            except ClientError as e:
                logger.warning(f"Failed to list S3 backups: {e}")

        return sorted(backups, key=lambda x: x['created'], reverse=True)


def main():
    """Main backup script entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='PragmaticHost Backup System')
    parser.add_argument(
        '--backup-dir',
        default='/backups/pragmatichost',
        help='Local backup directory'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List available backups'
    )
    parser.add_argument(
        '--restore',
        help='Restore from backup file'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    backup_system = PragmaticHostBackup(backup_dir=args.backup_dir)

    if args.list:
        backups = backup_system.list_backups()
        print(f"\nAvailable backups ({len(backups)} total):")
        print("=" * 80)
        for backup in backups:
            print(f"Name: {backup['name']}")
            print(f"Created: {backup['created']}")
            print(f"Size: {backup['size']:,} bytes")
            print(f"Location: {backup['location']}")
            print(f"Path: {backup['path']}")
            print("-" * 40)
        return

    if args.restore:
        success = backup_system.restore_backup(args.restore)
        if success:
            print("Restore completed successfully")
        else:
            print("Restore failed")
            sys.exit(1)
        return

    # Create backup
    success = backup_system.create_full_backup()
    if success:
        print("Backup completed successfully")
    else:
        print("Backup failed")
        sys.exit(1)


if __name__ == '__main__':
    main()

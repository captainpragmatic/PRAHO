#!/usr/bin/env python3
"""
PRAHO PLATFORM - Deployment Script
===============================================================================
Automated deployment system for Romanian hosting provider production environment
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pragmatichost/deploy.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class PragmaticHostDeployment:
    """
    Romanian hosting provider deployment system
    
    Features:
    - Git-based deployment
    - Zero-downtime deployments
    - Database migrations
    - Static file collection
    - Service restart
    - Rollback capability
    - Health checks
    - Notification system
    """

    def __init__(self, config_file: str = '/etc/pragmatichost/deploy.json'):
        """
        Initialize deployment system
        
        Args:
            config_file: Path to deployment configuration file
        """
        self.config_file = Path(config_file)
        self.config = self._load_config()

        # Deployment paths
        self.app_dir = Path(self.config['app_dir'])
        self.releases_dir = self.app_dir / 'releases'
        self.shared_dir = self.app_dir / 'shared'
        self.current_link = self.app_dir / 'current'

        # Create directory structure
        self.releases_dir.mkdir(parents=True, exist_ok=True)
        self.shared_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Initialized PragmaticHost deployment system")

    def _load_config(self) -> dict[str, Any]:
        """Load deployment configuration"""
        default_config = {
            'app_dir': '/opt/pragmatichost',
            'app_user': 'pragmatichost',
            'git_repo': 'https://github.com/pragmatichost/praho platform.git',
            'git_branch': 'main',
            'python_path': '/opt/pragmatichost/.venv/bin/python',
            'pip_path': '/opt/pragmatichost/.venv/bin/pip',
            'services': ['gunicorn', 'nginx', 'redis-server', 'postgresql'],
            'health_check_url': 'http://localhost:8000/health/',
            'health_check_timeout': 30,
            'keep_releases': 5,
            'backup_before_deploy': True,
            'run_migrations': True,
            'collect_static': True,
            'notification_email': 'admin@pragmatichost.com',
        }

        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config file {self.config_file}: {e}")

        return default_config

    def deploy(self, branch: str | None = None, skip_backup: bool = False) -> bool:
        """
        Deploy the application
        
        Args:
            branch: Git branch to deploy (defaults to config)
            skip_backup: Skip backup creation
            
        Returns:
            True if deployment was successful
        """
        deploy_branch = branch or self.config['git_branch']
        release_name = datetime.now().strftime('%Y%m%d_%H%M%S')
        release_dir = self.releases_dir / release_name

        try:
            logger.info(f"Starting deployment: {release_name} (branch: {deploy_branch})")

            # 1. Create backup (if enabled)
            if self.config['backup_before_deploy'] and not skip_backup:
                if not self._create_backup():
                    logger.error("Backup failed, aborting deployment")
                    return False

            # 2. Clone repository
            if not self._clone_repository(release_dir, deploy_branch):
                return False

            # 3. Setup shared files and directories
            if not self._setup_shared_resources(release_dir):
                return False

            # 4. Install dependencies
            if not self._install_dependencies(release_dir):
                return False

            # 5. Run database migrations
            if self.config['run_migrations']:
                if not self._run_migrations(release_dir):
                    return False

            # 6. Collect static files
            if self.config['collect_static']:
                if not self._collect_static_files(release_dir):
                    return False

            # 7. Update symlink (atomic deployment)
            if not self._update_current_symlink(release_dir):
                return False

            # 8. Restart services
            if not self._restart_services():
                return False

            # 9. Health check
            if not self._health_check():
                logger.error("Health check failed, rolling back...")
                self._rollback()
                return False

            # 10. Cleanup old releases
            self._cleanup_old_releases()

            logger.info(f"Deployment completed successfully: {release_name}")
            self._send_deployment_notification(True, release_name, deploy_branch)

            return True

        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            self._send_deployment_notification(False, release_name, deploy_branch, str(e))
            return False

    def _create_backup(self) -> bool:
        """Create backup before deployment"""
        try:
            logger.info("Creating pre-deployment backup...")

            # Use the backup script
            backup_script = Path(__file__).parent / 'backup.py'
            if not backup_script.exists():
                logger.warning("Backup script not found, skipping backup")
                return True

            cmd = [sys.executable, str(backup_script)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Backup failed: {result.stderr}")
                return False

            logger.info("Pre-deployment backup completed")
            return True

        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return False

    def _clone_repository(self, release_dir: Path, branch: str) -> bool:
        """Clone the git repository"""
        try:
            logger.info(f"Cloning repository to {release_dir}...")

            cmd = [
                'git', 'clone',
                '--branch', branch,
                '--depth', '1',
                self.config['git_repo'],
                str(release_dir)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Git clone failed: {result.stderr}")
                return False

            logger.info("Repository cloned successfully")
            return True

        except Exception as e:
            logger.error(f"Repository clone failed: {e}")
            return False

    def _setup_shared_resources(self, release_dir: Path) -> bool:
        """Setup shared files and directories"""
        try:
            logger.info("Setting up shared resources...")

            # Shared items (linked between releases)
            shared_items = [
                'logs',
                'media',
                'static',
                '.env',
                'db.sqlite3',  # For SQLite deployments
            ]

            for item in shared_items:
                shared_path = self.shared_dir / item
                release_path = release_dir / item

                # Create shared item if it doesn't exist
                if not shared_path.exists():
                    if item in ['logs', 'media', 'static']:
                        shared_path.mkdir(parents=True, exist_ok=True)
                    else:
                        shared_path.touch()

                # Remove release item if it exists
                if release_path.exists():
                    if release_path.is_dir():
                        release_path.rmdir()
                    else:
                        release_path.unlink()

                # Create symlink
                release_path.symlink_to(shared_path)

            logger.info("Shared resources setup completed")
            return True

        except Exception as e:
            logger.error(f"Shared resources setup failed: {e}")
            return False

    def _install_dependencies(self, release_dir: Path) -> bool:
        """Install Python dependencies"""
        try:
            logger.info("Installing dependencies...")

            # Install from requirements/prod.txt
            requirements_file = release_dir / 'requirements' / 'prod.txt'
            if not requirements_file.exists():
                requirements_file = release_dir / 'requirements.txt'

            if not requirements_file.exists():
                logger.warning("No requirements file found")
                return True

            cmd = [
                self.config['pip_path'],
                'install',
                '--upgrade',
                '--requirement',
                str(requirements_file)
            ]

            result = subprocess.run(
                cmd,
                cwd=str(release_dir),
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"Pip install failed: {result.stderr}")
                return False

            logger.info("Dependencies installed successfully")
            return True

        except Exception as e:
            logger.error(f"Dependencies installation failed: {e}")
            return False

    def _run_migrations(self, release_dir: Path) -> bool:
        """Run database migrations"""
        try:
            logger.info("Running database migrations...")

            cmd = [
                self.config['python_path'],
                'manage.py',
                'migrate',
                '--noinput'
            ]

            env = os.environ.copy()
            env['DJANGO_SETTINGS_MODULE'] = 'config.settings.prod'

            result = subprocess.run(
                cmd,
                cwd=str(release_dir),
                env=env,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"Migrations failed: {result.stderr}")
                return False

            logger.info("Database migrations completed")
            return True

        except Exception as e:
            logger.error(f"Migrations failed: {e}")
            return False

    def _collect_static_files(self, release_dir: Path) -> bool:
        """Collect static files"""
        try:
            logger.info("Collecting static files...")

            cmd = [
                self.config['python_path'],
                'manage.py',
                'collectstatic',
                '--noinput',
                '--clear'
            ]

            env = os.environ.copy()
            env['DJANGO_SETTINGS_MODULE'] = 'config.settings.prod'

            result = subprocess.run(
                cmd,
                cwd=str(release_dir),
                env=env,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"Static files collection failed: {result.stderr}")
                return False

            logger.info("Static files collected successfully")
            return True

        except Exception as e:
            logger.error(f"Static files collection failed: {e}")
            return False

    def _update_current_symlink(self, release_dir: Path) -> bool:
        """Update the current symlink (atomic deployment)"""
        try:
            logger.info("Updating current symlink...")

            # Create temporary symlink
            temp_link = self.app_dir / f'current_tmp_{os.getpid()}'
            temp_link.symlink_to(release_dir)

            # Atomic move (replace current symlink)
            temp_link.replace(self.current_link)

            logger.info("Current symlink updated successfully")
            return True

        except Exception as e:
            logger.error(f"Symlink update failed: {e}")
            return False

    def _restart_services(self) -> bool:
        """Restart application services"""
        try:
            logger.info("Restarting services...")

            # Services that need restarting
            restart_services = ['gunicorn']  # Only restart app server

            for service in restart_services:
                if service in self.config['services']:
                    logger.info(f"Restarting {service}...")

                    cmd = ['sudo', 'systemctl', 'restart', service]
                    result = subprocess.run(cmd, capture_output=True, text=True)

                    if result.returncode != 0:
                        logger.error(f"Failed to restart {service}: {result.stderr}")
                        return False

                    # Wait a bit for service to start
                    time.sleep(2)

            logger.info("Services restarted successfully")
            return True

        except Exception as e:
            logger.error(f"Service restart failed: {e}")
            return False

    def _health_check(self) -> bool:
        """Perform application health check"""
        try:
            logger.info("Performing health check...")

            import requests

            url = self.config['health_check_url']
            timeout = self.config['health_check_timeout']

            # Wait for application to start
            for attempt in range(5):
                try:
                    response = requests.get(url, timeout=timeout)
                    if response.status_code == 200:
                        logger.info("Health check passed")
                        return True
                except requests.RequestException:
                    if attempt < 4:
                        logger.info(f"Health check attempt {attempt + 1} failed, retrying...")
                        time.sleep(5)
                    continue

            logger.error("Health check failed after 5 attempts")
            return False

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    def _rollback(self) -> bool:
        """Rollback to previous release"""
        try:
            logger.info("Rolling back to previous release...")

            # Find previous release
            releases = sorted([
                d for d in self.releases_dir.iterdir()
                if d.is_dir() and d.name != self.current_link.resolve().name
            ], key=lambda x: x.name, reverse=True)

            if not releases:
                logger.error("No previous release found for rollback")
                return False

            previous_release = releases[0]

            # Update symlink to previous release
            if not self._update_current_symlink(previous_release):
                return False

            # Restart services
            if not self._restart_services():
                return False

            logger.info(f"Rolled back to release: {previous_release.name}")
            return True

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False

    def _cleanup_old_releases(self):
        """Remove old releases"""
        try:
            logger.info("Cleaning up old releases...")

            # Get all releases sorted by creation time
            releases = sorted([
                d for d in self.releases_dir.iterdir() if d.is_dir()
            ], key=lambda x: x.name, reverse=True)

            # Keep only the specified number of releases
            keep_count = self.config['keep_releases']
            to_remove = releases[keep_count:]

            for release in to_remove:
                logger.info(f"Removing old release: {release.name}")
                subprocess.run(['rm', '-rf', str(release)])

            logger.info(f"Cleaned up {len(to_remove)} old releases")

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    def _send_deployment_notification(
        self,
        success: bool,
        release_name: str,
        branch: str,
        error: str | None = None
    ):
        """Send deployment notification email"""
        try:
            # Import Django for email functionality
            os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.prod')
            import django
            django.setup()

            from django.conf import settings
            from django.core.mail import send_mail

            if success:
                subject = f"PragmaticHost: Deployment Successful - {release_name}"
                message = f"Deployment completed successfully.\n\nRelease: {release_name}\nBranch: {branch}"
            else:
                subject = f"PragmaticHost: Deployment FAILED - {release_name}"
                message = f"Deployment failed!\n\nRelease: {release_name}\nBranch: {branch}\nError: {error}"

            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [self.config['notification_email']],
                fail_silently=True
            )

        except Exception as e:
            logger.error(f"Failed to send deployment notification: {e}")

    def list_releases(self) -> list[dict[str, Any]]:
        """List all releases"""
        releases = []

        for release_dir in sorted(self.releases_dir.iterdir(), key=lambda x: x.name, reverse=True):
            if release_dir.is_dir():
                is_current = (
                    self.current_link.exists() and
                    self.current_link.resolve() == release_dir
                )

                releases.append({
                    'name': release_dir.name,
                    'path': str(release_dir),
                    'created': datetime.strptime(release_dir.name, '%Y%m%d_%H%M%S'),
                    'current': is_current
                })

        return releases


def main():
    """Main deployment script entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='PragmaticHost Deployment System')
    parser.add_argument(
        '--config',
        default='/etc/pragmatichost/deploy.json',
        help='Deployment configuration file'
    )
    parser.add_argument(
        '--branch',
        help='Git branch to deploy'
    )
    parser.add_argument(
        '--skip-backup',
        action='store_true',
        help='Skip backup creation'
    )
    parser.add_argument(
        '--rollback',
        action='store_true',
        help='Rollback to previous release'
    )
    parser.add_argument(
        '--list-releases',
        action='store_true',
        help='List all releases'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    deployment = PragmaticHostDeployment(config_file=args.config)

    if args.list_releases:
        releases = deployment.list_releases()
        print(f"\nReleases ({len(releases)} total):")
        print("=" * 60)
        for release in releases:
            current_marker = " (CURRENT)" if release['current'] else ""
            print(f"Release: {release['name']}{current_marker}")
            print(f"Created: {release['created']}")
            print(f"Path: {release['path']}")
            print("-" * 40)
        return

    if args.rollback:
        success = deployment._rollback()
        if success:
            print("Rollback completed successfully")
        else:
            print("Rollback failed")
            sys.exit(1)
        return

    # Deploy
    success = deployment.deploy(branch=args.branch, skip_backup=args.skip_backup)
    if success:
        print("Deployment completed successfully")
    else:
        print("Deployment failed")
        sys.exit(1)


if __name__ == '__main__':
    main()

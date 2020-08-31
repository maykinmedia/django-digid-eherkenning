from .settings import *

INSTALLED_APPS += ["django_jenkins"]
# PROJECT_APPS = ["digid_eherkenning", "tests.project"]
JENKINS_TASKS = ("django_jenkins.tasks.run_pep8",)

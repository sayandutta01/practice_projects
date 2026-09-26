# Deliberately insecure code used only to test email notification.
import subprocess

subprocess.run(
    "echo email notification test",
    shell=True,
    check=True,
)
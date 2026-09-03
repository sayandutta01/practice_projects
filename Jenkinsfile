// Jenkins security pipeline triggered by GitHub push
pipeline {
    agent any

    stages {
        stage('Verify Checkout') {
            steps {
                bat 'echo Jenkins successfully downloaded practice_projects'
                bat 'dir'
            }
        }

        stage('Check Python') {
            steps {
                bat 'py -3.11 --version'
            }
        }

        stage('Prepare Security Tools') {
            steps {
                bat 'py -3.11 -m venv .jenkins-venv'
                bat '.jenkins-venv\\Scripts\\python.exe -m pip install --upgrade pip'
                bat '.jenkins-venv\\Scripts\\python.exe -m pip install bandit==1.9.4'
            }
        }
    }
}
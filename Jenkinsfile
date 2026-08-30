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
    }
}
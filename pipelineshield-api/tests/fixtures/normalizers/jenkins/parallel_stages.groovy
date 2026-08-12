// Parallel stages in a declarative pipeline
pipeline {
    agent any

    triggers {
        cron('H/15 * * * *')
        pollSCM('H/5 * * * *')
    }

    stages {
        stage('Parallel Tests') {
            parallel {
                stage('Unit Tests') {
                    steps {
                        sh 'pytest tests/unit/'
                    }
                }
                stage('Integration Tests') {
                    steps {
                        sh 'pytest tests/integration/'
                    }
                }
                stage('Lint') {
                    steps {
                        sh 'flake8 src/'
                    }
                }
            }
        }
        stage('Deploy') {
            steps {
                sh './deploy.sh'
            }
        }
    }
}

// Nested stages and environment block
pipeline {
    agent any

    environment {
        APP_NAME = 'myapp'
        BUILD_VERSION = '1.0.0'
    }

    stages {
        stage('Prepare') {
            steps {
                sh 'echo "Preparing build for ${APP_NAME}"'
            }
        }
        stage('Build') {
            steps {
                sh 'make clean'
                sh 'make build'
            }
        }
        stage('Test') {
            steps {
                sh 'make test'
                sh 'make coverage'
            }
        }
        stage('Package') {
            steps {
                sh 'make package'
            }
        }
    }

    post {
        always {
            sh 'make clean'
        }
        success {
            echo 'Build succeeded'
        }
    }
}

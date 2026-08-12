// Jenkinsfile with @Library shared library import
@Library('my-shared-library@main') _

pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        stage('Security Scan') {
            steps {
                // Using a function from the shared library
                sh 'trivy image myapp:latest'
            }
        }
    }
}

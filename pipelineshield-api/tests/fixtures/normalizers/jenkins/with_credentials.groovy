// Jenkinsfile with withCredentials and environment credentials
pipeline {
    agent {
        docker {
            image 'python:3.11'
        }
    }

    environment {
        DEPLOY_TOKEN = credentials('deploy-token-id')
        REGISTRY_CREDS = credentials('docker-registry')
    }

    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:latest .'
            }
        }
        stage('Push') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'docker-registry', usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh 'echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin'
                    sh 'docker push myapp:latest'
                }
            }
        }
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'prod-api-key', variable: 'API_KEY')]) {
                    sh 'curl -H "Authorization: Bearer $API_KEY" https://api.example.com/deploy'
                }
            }
        }
    }
}

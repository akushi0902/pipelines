// Minimal declarative Jenkinsfile — two stages, Docker agent
pipeline {
    agent {
        docker {
            image 'node:20'
        }
    }

    stages {
        stage('Build') {
            steps {
                sh 'npm ci'
                sh 'npm run build'
            }
        }
        stage('Test') {
            steps {
                sh 'npm test'
            }
        }
    }
}

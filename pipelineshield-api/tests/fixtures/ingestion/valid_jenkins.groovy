// Jenkinsfile: script block + shared library
@Library('deploy-utils@main') _

pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        stage('Scripted Step') {
            steps {
                script {
                    def tag = sh(returnStdout: true, script: 'git describe --tags').trim()
                    echo "Tag: ${tag}"
                }
            }
        }
    }
}

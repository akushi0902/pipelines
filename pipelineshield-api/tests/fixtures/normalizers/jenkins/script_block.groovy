// Jenkinsfile with script { } block (partially Not Assessable)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        stage('Conditional Deploy') {
            steps {
                script {
                    // This is arbitrary Groovy — Not Assessable
                    def version = sh(returnStdout: true, script: 'git describe --tags').trim()
                    if (version.startsWith('v')) {
                        sh "docker push myapp:${version}"
                    } else {
                        echo "Not a release tag, skipping deploy"
                    }
                }
            }
        }
        stage('Notify') {
            steps {
                sh 'echo "Done"'
            }
        }
    }
}

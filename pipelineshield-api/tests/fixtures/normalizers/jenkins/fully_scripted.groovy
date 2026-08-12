// Fully scripted Jenkinsfile — no pipeline { } block
// Entire file is Not Assessable
node('linux') {
    stage('Checkout') {
        checkout scm
    }

    stage('Build') {
        sh 'make build'
    }

    stage('Test') {
        try {
            sh 'make test'
        } catch (Exception e) {
            currentBuild.result = 'FAILURE'
            throw e
        }
    }

    stage('Deploy') {
        if (env.BRANCH_NAME == 'main') {
            sh './deploy.sh production'
        }
    }
}

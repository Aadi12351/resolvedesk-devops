pipeline {
  agent { label 'resolvedesk-build' }
  options { disableConcurrentBuilds(); timeout(time: 20, unit: 'MINUTES') }
  stages {
    stage('Checkout') { steps { checkout scm } }
    stage('Test') {
      steps {
        sh 'docker build -f Dockerfile.test -t resolvedesk-tests:$BUILD_NUMBER .'
        sh 'mkdir -p reports && docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$WORKSPACE/reports:/reports" resolvedesk-tests:$BUILD_NUMBER'
      }
      post { always { junit testResults: 'reports/tests.xml', allowEmptyResults: false } }
    }
    stage('Build Application') { steps { sh 'docker build -t resolvedesk:$BUILD_NUMBER .' } }
  }
  post { always { archiveArtifacts artifacts: 'reports/*', allowEmptyArchive: true } }
}

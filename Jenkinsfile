pipeline {
    agent any

    environment {
        CIMON_CLIENT_ID = credentials("cimon-client-id")
        CIMON_SECRET = credentials("cimon-secret")
        CIMON_ALLOWED_HOSTS = """
            registry.npmjs.org
            nodejs.org
            github.com
            api.github.com
            objects.githubusercontent.com
        """
    }

    options {
        disableConcurrentBuilds()
    }

    stages {
        stage('Check out Git repository') {
            steps {
                checkout scm
            }
        }

        stage('Install Cimon') {
            steps {
                sh 'curl -sSfL https://cimon-releases.s3.amazonaws.com/install.sh | sudo sh -s -- -b /usr/local/bin'
            }
        }

        stage('CIMON - Start runtime security monitor') {
            steps {
                sh 'sudo -E cimon agent start-background'
            }
        }

        stage('Use Node.js 24') {
            steps {
                sh 'curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -'
                sh 'sudo apt-get install -y nodejs'
            }
        }

        stage('Install application') {
            steps {
                sh 'npm install --ignore-scripts'
                sh 'cd frontend && npm install --ignore-scripts'
            }
        }
    }

    post {
        always {
            sh 'sudo -E cimon agent stop'
        }
    }
}


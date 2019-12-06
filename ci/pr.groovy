#!/usr/bin/env groovy
@Library('gcx@v1.9') _

agent("docker") {
    stage('checkout') {
        gitCheckout(false)
    }
    stage('test') {
        docker.image("google/dart:2.3").inside("--env PUB_CACHE=$WORKSPACE/.pub_cache") {
            sh "pub get"
            sh "pub run test"
            sh "pub run tool/reformat.dart"
        }
    }
}

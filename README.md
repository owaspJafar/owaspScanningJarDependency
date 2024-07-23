# Introduction of dependency
---
**owaspScanningJarDependency**

This library has been developed to make it easier for programmers to use [owasp:dependency-check]([https://www.example.com)](https://github.com/jeremylong/DependencyCheck) in Java and is available to you for free.

---
# Dependency application

Find dependencies that are vulnerable and dangerous for commercial applications
---
# Usages
---

Use this dependency in your build.gradle file to reference this library in your project

# Step 1
Add the JitPack repository to your build file. Add it in your root build.gradle at the end of repositories:
`allprojects {
        repositories {
            ...
            maven { url "https://jitpack.io" }
        }
    }`


add code  to File build.gradle in intellij idea

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:3.1.2'
    }
}


plugins {
    id 'java'
    id 'org.owasp.dependencycheck' version '6.2.2'
}
apply plugin: 'org.owasp.dependencycheck'

group 'org.example'
version '1.0-SNAPSHOT'

repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}
dependencyCheck {
    formats = ['HTML', 'XML','json']
    outputDirectory = file('build/jafar-report')


}

and add 
dependencies {
 implementation 'com.github.owaspJafar:owaspScanningJarDependency:1.0.6'

}

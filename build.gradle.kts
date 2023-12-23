/*
	dynip-client gradle build file.
 */

plugins {
	id("java");

	/*id("application");*/
	/*apply plugin: 'application'*/
	/*mainClassName = 'hello.HelloWorld'*/
}

java {
    sourceCompatibility = JavaVersion.VERSION_19;
    targetCompatibility = JavaVersion.VERSION_19;
}

tasks.withType(Jar::class) {
	manifest {
		attributes["Main-Class"] = "cc.tools.dynip.client.IpClient";
	}
}

tasks.javadoc() {
	/* source = sourceSets["main"].allJava; */
	/*destinationDir = File("html/javadoc");*/
	options.memberLevel = JavadocMemberLevel.PRIVATE;
}

tasks.clean() {
	doLast {
    	/*File("html/javadoc").delete();*/
    }
}

repositories {
	mavenCentral();
}

dependencies {
	testImplementation("junit:junit:4.13.2");
}

tasks.jar() {
	/*from("src/main/java");*/
}



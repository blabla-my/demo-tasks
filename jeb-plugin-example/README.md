# Jeb plugin examples

## Change logs
These examples are from https://github.com/pnfsoftware/jeb-samplecode, but we have made some modifications:

1. Change to use maven instead of ant. 
2. Change to Jeb4 api instead of Jeb3 api.

## Prerequisites
1. JDK >= 11. Check use by using `java -version`.
2. Maven. Maven is a project management tool. https://maven.apache.org/
3. Jeb 4.20 or later

## Build a jeb plugin package (.jar file)
1. Install the jeb.jar to maven.
    ```bash
    # under jeb-plugin-example/
    $ mvn install:install-file -Dfile="path_to_your_jeb_installation/bin/app/jeb.jar" -DgroupId="com.pnfsoftware.jeb" -DartifactId="jeb" -Dversion="4.20" -Dpackaging="jar" -DgeneratePom=true
    ```
2. find tag `<JebPlugin-entryclass>` in `pom.xml`. It adds a JebPlugin-entryclass property to the MANIFEST of generated .jar file, which tells the jeb which class to load. Modify it to the plugin class you want to use, e.g., `com.pnf.vtplugin.VirustotalReportPlugin`,`com.pnf.pommePlugin.PommePlugin`.

3. use maven to build the package.
    ```shell
    # under jev-plugin-example
    mvn package 
    ```
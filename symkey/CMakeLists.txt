project(symkey)

javac(symkey-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${JAVAC_CLASSPATH}
        ${CLASSES_OUTPUT_DIR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    HEADER_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/include
    DEPENDS
        generate_java
)

# TODO: merge into jss.jar
jar(symkey-jar
    CREATE
        ${CMAKE_CURRENT_BINARY_DIR}/jss-symkey.jar
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-classes
)

set(SYMKEY_JAR ${CMAKE_BINARY_DIR}/jss-symkey.jar CACHE INTERNAL "symkey jar file")

set(SYMKEY_PUBLIC_INCLUDE_DIRS
    ${CMAKE_CURRENT_BINARY_DIR}/src/main/java/org/mozilla/jss/symkey
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/java/org/mozilla/jss/symkey
    CACHE INTERNAL "symkey public include directories"
)

set(SYMKEY_PRIVATE_INCLUDE_DIRS
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${JNI_INCLUDE_DIRS}
    ${NSPR_INCLUDE_DIRS}
    ${NSS_INCLUDE_DIRS}
)

set(SYMKEY_SHARED_LIBRARY symkey_library CACHE INTERNAL "symkey shared library")

set(symkey_library_SRCS
    src/main/java/org/mozilla/jss/symkey/Buffer.cpp
    src/main/java/org/mozilla/jss/symkey/EncryptData.cpp
    src/main/java/org/mozilla/jss/symkey/SessionKey.cpp
    src/main/java/org/mozilla/jss/symkey/SymKey.cpp
    src/main/java/org/mozilla/jss/symkey/NistSP800_108KDF.cpp
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)

add_custom_target(
    symkey-so ALL
    DEPENDS
        symkey-jar
    COMMENT
       "Building symkey shared library")

foreach(source ${symkey_library_SRCS})

    get_filename_component(name ${source} NAME_WE)
    get_filename_component(ext ${source} EXT)
    get_filename_component(dir ${source} DIRECTORY)

    # /usr/bin/c++
    #     -I${CMAKE_CURRENT_BINARY_DIR}/include
    #     -I/usr/lib/jvm/java/include
    #     -I/usr/lib/jvm/java/include/linux
    #     -I/usr/include/nspr4
    #     -I/usr/include/nss3
    #     -fPIC
    #     -o ${CMAKE_CURRENT_BINARY_DIR}/lib/<filename>.o
    #     -c ${CMAKE_CURRENT_SOURCE_DIR}/src/main/java/org/mozilla/jss/symkey/<filename>.cpp
    add_custom_command(
        TARGET
            symkey-so
        COMMAND
            ${CMAKE_CXX_COMPILER}
            -I${CMAKE_CURRENT_BINARY_DIR}/include
            -I/usr/lib/jvm/java/include
            -I/usr/lib/jvm/java/include/linux
            -I/usr/include/nspr4
            -I/usr/include/nss3
            -fPIC
            -o ${CMAKE_CURRENT_BINARY_DIR}/lib/${name}.o
            -c ${CMAKE_CURRENT_SOURCE_DIR}/${dir}/${name}${ext}
        COMMENT
            "Building symkey/lib/${name}.o"
    )
endforeach()

# /usr/bin/c++
#     -o libjss-symkey.so
#     -lsmime3 -lssl3 -lnss3 -lnssutil3 -lplc4 -lplds4 -lnspr4 -lpthread -ldl
#     -fPIC -shared -Wl,-soname,libjss-symkey.so
#     ${CMAKE_CURRENT_BINARY_DIR}/lib/*.o
add_custom_command(
    TARGET
        symkey-so
    COMMAND
        ${CMAKE_CXX_COMPILER}
        -o libjss-symkey.so
        ${JSS_LD_FLAGS}
        -fPIC -shared -Wl,-soname,libjss-symkey.so
        ${CMAKE_CURRENT_BINARY_DIR}/lib/*.o
    COMMENT
        "Building symkey/lib/libjss-symkey.so"
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/jss-symkey.jar
    DESTINATION
        ${JNI_DIR}
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/libjss-symkey.so
    DESTINATION
        ${LIB_DIR}/jss
)

install(
    CODE "execute_process(
        COMMAND ln -sf ../../../${JNI_DIR}/jss-symkey.jar \$ENV{DESTDIR}${LIB_DIR}/jss/jss-symkey.jar
    )"
)

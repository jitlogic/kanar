#!/bin/bash

APP_CMD="$1"

if [ -z "$APP_CMD" ] ; then
    echo "Usage: $0 {start|stop|run|status}"
    exit 1
fi

KANAR_HOME="$(dirname $0)"

if [ -z "$KANAR_HOME" ] ; then
    KANAR_HOME=$PWD
fi

if [[ "$KANAR_HOME" == '.' || "$KANAR_HOME" =~ ^\.\.?/.* ]] ; then
  KANAR_HOME="$PWD/$KANAR_HOME"
fi

for F in kanar.conf jvm.conf kanar.jar ; do
  if [ ! -f $KANAR_HOME/$F ] ; then
    echo "Incomplete KANAR installation: missing $F file in $KANAR_HOME."
  fi
done

for D in logs ; do
  if [ ! -d $KANAR_HOME/$D ] ; then
    echo "Missing directory: $KANAR_HOME/$D. Creating..."
    mkdir $KANAR_HOME/$D
  fi
done

if [ -f $KANAR_HOME/jvm.conf ] ; then
    . $KANAR_HOME/jvm.conf
fi

if [ -z "$JAVA_HOME" ] ; then
  echo "Missing JAVA_HOME setting. Add JAVA_HOME=/path/to/jdk7 to $KANAR_HOME/jvm.conf."
  exit 1
fi

if [ -z "$APP_NAME" ] ; then
  APP_NAME="kanar"
fi

status() {
    pgrep -f "Dkanar.app=$APP_NAME" >/dev/null
}

start() {
    if status ; then
      echo "KANAR is running."
    else
      echo -n "Starting KANAR ..."
      cd $KANAR_HOME
      setsid $JAVA_HOME/bin/java -Dkanar.app=$APP_NAME $JAVA_OPTS -Dkanar.home=$KANAR_HOME -jar kanar.jar >$KANAR_HOME/logs/console.log 2>&1 &
      echo "OK."
    fi
}

run() {
    if status ; then
      echo "Another KANAR instance is running."
    else
      echo "Starting KANAR at $KANAR_HOME"
      cd $KANAR_HOME
      $JAVA_HOME/bin/java -Dkanar.app=$APP_NAME -Dkanar.home=$KANAR_HOME $JAVA_OPTS -jar kanar.jar
    fi
}

stop() {
    if status ; then
      echo -n "Stopping KANAR ..."
      pkill -f Dkanar.app=$APP_NAME >/dev/null
      echo "OK"
    else
      echo -n "KANAR already stopped."
    fi
}

case "$APP_CMD" in
start)
    start
    ;;
stop)
    stop
    ;;
run)
    run
    ;;
status)
    if status ; then
      echo "KANAR is running."
      exit 0
    else
      echo "KANAR is not running."
      exit 1
    fi
    ;;
esac


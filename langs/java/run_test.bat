javac -cp "swig_generated" test.java
java "-Djava.library.path=swig_generated" -cp "swig_generated;." test
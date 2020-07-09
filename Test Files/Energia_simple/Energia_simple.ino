int function(int i) {
  if (i % 2 == 0) {
    return(i+4);
  } else {
    return(i + 1);
  }
}

void setup() {
  Serial.println(function(2));
  // put your setup code here, to run once:

}

void loop() {
  // put your main code here, to run repeatedly: 
  
}

char * func1(int i) {
  char buffer[i];
  for (int j = 0; j < 30; j++) {
    buffer[j] = 0; 
  }

  return buffer;
}

void setup() {
  Serial.println(func1(10));
  // put your setup code here, to run once:

}

void loop() {
  // put your main code here, to run repeatedly:

}

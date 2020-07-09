int sketchyFunc(int input) {
  for(int i = 0; i < 8; i++) {
    if (i == 7) {
      return i + input;
    }
  }
}

int sketchyFunc2(int input) {
  for(int i = 0; i < 8; i++) {
    if (i == 7) {
      return i - input;
    }
  }
}

void setup() {
  // put your setup code here, to run once:
  int a = sketchyFunc(2);
  int b = sketchyFunc2(4);
  Serial.print(a);
  Serial.print(b);
}

void loop() {
  // put your main code here, to run repeatedly:

}

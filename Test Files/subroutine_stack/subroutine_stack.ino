char * func1(int i) {
  char buffer[i];
  for (int j = 0; j < i; j++) {
    buffer[j] = 0; 
  }
  return buffer;
}

int func2(int i) {
  int j;
  int k;
  int l;
  int j1;
  int k1;
  int l1;
  int j2;
  int k2;
  int l2;
  int j3;
  int k3;
  int l3;
  int j4;
  int k4;
  int l4;
  int j5;
  int k5;
  int l5;
  int j6;
  int k6;
  int l6;
  int j7;
  int k7;
  int l7;
  if(i % 2 == 0) {
    j = i + 7;
  }
  if(j % 3 == 0) {
    k = j++;
  }
  if(k % 5 == 0) {
    l = k + 19;
  }
  j1 = l + 7;
  k1 = j1 + k;
  l1 = j1 + k1;
  j2 = l1 + 7;
  k2 = j2 + k;
  l2 = j2 + k2;
  j3 = l2 + 7;
  k3 = j2 + k1;
  l3 = j1 + k1;
  j4 = l3 + 7;
  k4 = j3 + k2;
  l4 = j2 + k1;
  j5 = l3 + 7;
  k5 = j5 + k;
  l5 = j4 + k4;
  j6 = l2 + 7;
  k6 = j2 + k2;
  l6 = j3 + k3;
  j7 = l5 + 7;
  k7 = j1 + k6;
  l7 = j2 + k6;
  return(j + k + l + j1 + j2 + j3 + j4 + j5 + j6 + j7 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + l1 + l2 + l3 + l4 + l5 + l6 + l7);
}

void setup() {
  Serial.println(func1(10));
  Serial.println(func2(2));
  // put your setup code here, to run once:

}

void loop() {
  // put your main code here, to run repeatedly:

}

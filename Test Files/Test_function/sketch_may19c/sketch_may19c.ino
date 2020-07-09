void banana() {
  pinMode(7, OUTPUT);
  
  
}

void setup() {
  volatile int a = 10;
  volatile int b = 0;

  if(b > a)
  {
    b = 20;
  }
  else 
  {
    b = 10;
  }
}

void loop() {
  volatile int b = 0;
  for(int i = 0; i < 10; i++)
  {
    b++;
  }

  volatile int product = b * 100;
  while (1) {
    
  }
}

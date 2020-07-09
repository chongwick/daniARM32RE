#define CSIZE sizeof(size_t)
/*
void __wrap_free(void *addr)
{
  if(addr){
    // prevent uaf
    memset(addr,0,*(size_t*)((size_t)addr-CSIZE));

    // check double free and overflow
    if(*(size_t*)((size_t)addr-CSIZE) == 0 || *(size_t*)((size_t)addr-CSIZE) != *(size_t*)((size_t)addr + *(size_t*)((size_t)addr-CSIZE))) {
        //raise(SIGSEGV);
    }
    __real_free((void*)((size_t)addr-CSIZE));
  }
}

void* __wrap_malloc(size_t len)
{
  void *addr = __real_malloc(len+2*CSIZE);
  if(addr){
      // add a parameter at the beginning and end
      *(size_t*)addr = len;
      *(size_t*)((size_t)addr+len+CSIZE) = len;
  } else {
    return NULL;
  }
  return (void*)((size_t)addr+CSIZE);
}

*/
struct stu{
  char *name;
};

struct mentor{
  char *name;
  struct stu *s;
};



void setup() {
  struct stu *stu1 = (struct stu *)malloc(sizeof(struct stu));
  stu1->name = "stu1";
  struct mentor *men1 = (struct mentor *)malloc(sizeof(struct mentor));
  men1->name = "mentor1";
  men1->s = stu1;

  free(men1);
  Serial.println(men1->s->name); //uaf here?

}

void loop() {
  // put your main code here, to run repeatedly:

}

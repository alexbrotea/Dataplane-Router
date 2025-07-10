#ifndef _LIST_H_
#define _LIST_H_

typedef struct cell *list;

struct cell
{
  void *element;
  list next;
};

extern list constr(void *element, list l);
extern list cdr_and_free(list l);

#endif /* _LIST_H_ */

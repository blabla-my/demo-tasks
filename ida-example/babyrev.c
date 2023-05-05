#include <malloc.h>
#include <stdio.h>
typedef struct _Node {
  int val;
  struct _Node *next;
} Node;

typedef struct _List {
  Node *head;
} List;

Node *create() {
  Node *nodeptr = (Node *)malloc(sizeof(Node));
  nodeptr->next = NULL;
  nodeptr->val = 0;
  return nodeptr;
}

void insert(List *list, Node *node) {
  if (list) {
    if (!list->head) {
      list->head = node;
    } else {
      Node *cur = list->head;
      while (cur->next) {
        cur = cur->next;
      }
      cur->next = node;
      node->next = NULL;
    }
  }
}

void walk(List *list) {
  if (list) {
    Node *cur = list->head;
    while (cur) {
      printf("%d ", cur->val);
      cur = cur->next;
    }
  }
}

int main() {
  Node *n1 = create();
  List list;
  list.head = NULL;
  int i = 0;
  for (i = 0; i < 10; i++) {
    Node *newnode = create();
    newnode->val = i;
    insert(&list, newnode);
  }
  walk(&list);
}

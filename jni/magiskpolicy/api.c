#include "magiskpolicy.h"
#include "sepolicy.h"

int sepol_allow(char *s, char *t, char *c, char *p) {
#ifdef LOG_DEBUG
	printf("allow %s %s %s %s\n", s, t, c, p);
#endif
	return add_rule(s, t, c, p, AVTAB_ALLOWED, 0);
}

int sepol_deny(char *s, char *t, char *c, char *p) {
#ifdef LOG_DEBUG
	printf("deny %s %s %s %s\n", s, t, c, p);
#endif
	return add_rule(s, t, c, p, AVTAB_ALLOWED, 1);
}

int sepol_auditallow(char *s, char *t, char *c, char *p) {
#ifdef LOG_DEBUG
	printf("auditallow %s %s %s %s\n", s, t, c, p);
#endif
	return add_rule(s, t, c, p, AVTAB_AUDITALLOW, 0);
}

int sepol_auditdeny(char *s, char *t, char *c, char *p) {
#ifdef LOG_DEBUG
	printf("auditdeny %s %s %s %s\n", s, t, c, p);
#endif
	return add_rule(s, t, c, p, AVTAB_AUDITDENY, 0);
}

int sepol_typetrans(char *s, char *t, char *c, char *d, char *o) {
	if (o == NULL) {
		printf("add_trans %s %s %s %s\n", s, t, c ,d);
		return add_transition(s, t, c, d);
	} else {
		printf("add_file_trans %s %s %s %s %s\n", s, t, c ,d, o);
		return add_file_transition(s, t, c, d, o);
	}
}

int sepol_allowxperm(char *s, char *t, char *c, char *range) {
#ifdef LOG_DEBUG
	printf("allowxperm %s %s %s %s\n", s, t, c, range);
#endif
	return add_xperm_rule(s, t, c, range, AVTAB_XPERMS_ALLOWED, 0);
}

int sepol_auditallowxperm(char *s, char *t, char *c, char *range) {
#ifdef LOG_DEBUG
	printf("auditallowxperm %s %s %s %s\n", s, t, c, range);
#endif
	return add_xperm_rule(s, t, c, range, AVTAB_XPERMS_AUDITALLOW, 0);
}

int sepol_dontauditxperm(char *s, char *t, char *c, char *range) {
#ifdef LOG_DEBUG
	printf("dontauditxperm %s %s %s %s\n", s, t, c, range);
#endif
	return add_xperm_rule(s, t, c, range, AVTAB_XPERMS_DONTAUDIT, 0);
}

int sepol_permissive(char *s) {
#ifdef LOG_DEBUG
	printf("permissive %s\n", s);
#endif
	return set_domain_state(s, 1);
}

int sepol_enforce(char *s) {
#ifdef LOG_DEBUG
	printf("enforce %s\n", s);
#endif
	return set_domain_state(s, 0);
}

int sepol_create(char *s) {
#ifdef LOG_DEBUG
	printf("create %s\n", s);
#endif
	return create_domain(s);
}

int sepol_attradd(char *s, char *a) {
#ifdef LOG_DEBUG
	printf("attradd %s %s\n", s, a);
#endif
	return add_typeattribute(s, a);
}

int sepol_exists(char* source) {
	return !! hashtab_search(policydb->p_types.table, source);
}

/*
 * list.h
 *
 *  Created on: 2012-9-15
 *      Author: guofeng
 */

#ifndef LIST_H_
#define LIST_H_

//#define DOUBLE_LINK 1

/*
 * memory and operate flags:
 * 0000 0000
 * 	(count from right to left)
 * 	1.	whether alloc by system, if so, set this bit.
 * 	2.	whether the container have used this contain, if so, set this bit
 * 	3-8: unused now
 */
#define LIST_SYS_ALLOC	0x01
#define LIST_USED			0x02

struct list
{
	struct list *next;
//#if DOUBLE_LINK
	struct list *prev;
//#endif	/* DOUBLE_LINK */

	unsigned char flags;
};

#define get_container_ptr( self_ptr, self_name, container_type ) \
		(self_ptr == NULL ? NULL : (container_type *)((void *)self_ptr - (void *)&((container_type *)0)->self_name))

#define init_list( self_ptr ) do \
	{ \
		(self_ptr)->next = NULL; \
		(self_ptr)->prev = NULL; \
	} while(0)

/*
 * insert list node 'self_ptr' after 'target_ptr'
 */
#define insert_list( target_ptr, self_ptr ) do{ \
		if( target_ptr == NULL ) \
		{ \
			target_ptr = self_ptr; \
		} \
		else \
		{ \
			(self_ptr)->next = (target_ptr)->next; \
			(self_ptr)->prev = target_ptr; \
			if( (target_ptr)->next != NULL ) \
			{ \
				(target_ptr)->next->prev = self_ptr; \
			} \
			(target_ptr)->next = self_ptr; \
		} \
	}while(0)

#define insert_list_nonptr( target, self ) do{ \
			(self).next = (target).next; \
			(self).prev = &(target); \
			if( (target).next != NULL ) \
			{ \
				(target).next->prev = &(self); \
			} \
			(target).next = &(self); \
	}while(0)

#define delete_same_list( self_ptr ) do{ \
		if( (self_ptr)->prev != NULL ) \
		{ \
			(self_ptr)->prev->next = (self_ptr)->next; \
		} \
		if( (self_ptr)->next != NULL ) \
		{ \
			(self_ptr)->next->prev = (self_ptr)->prev; \
		} \
	}while(0)

#define prev_container( self_ptr, prev_connector_name, prev_container_name ) \
		(self_ptr == NULL ? NULL : get_container_ptr( (self_ptr)->prev, prev_connector_name, prev_container_name))

#define next_container( self_ptr, next_connector_name, next_container_name ) \
		(self_ptr == NULL ? NULL : get_container_ptr( (self_ptr)->next, next_connector_name, next_container_name))

#define foreach_list( var, self_ptr, connector_name, container_name ) for( var = get_container_ptr( self_ptr, connector_name, container_name ); var != NULL; var = next_container( &(var)->connector_name, connector_name, container_name ) )

#define have_next( self_ptr ) ((self_ptr)->next == NULL ? 0 : 1)

/* some micro relate to flags */
#define list_set_sys( self_ptr ) do{ (self_ptr)->flags |= LIST_SYS_ALLOC; }while(0)
#define list_set_usr( self_ptr ) do{ (self_ptr)->flags &= ~LIST_SYS_ALLOC; }while(0)

#define list_is_sys( self_ptr )	((self_ptr)->flags & LIST_SYS_ALLOC)
#define list_is_usr( self_ptr )	!list_is_sys( self_ptr )

#define list_set_used( self_ptr ) do{ (self_ptr)->flags |= LIST_USED; }while(0)
#define list_set_unused( self_ptr ) do{ (self_ptr)->flags &= ~LIST_USED; }while(0)

#define list_is_used( self_ptr )	((self_ptr)->flags & LIST_USED)
#define list_is_unused( self_ptr )	!list_is_used( self_ptr )

#endif	/* LIST_H_ */

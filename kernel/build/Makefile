# $FreeBSD$

.PATH: ../

KMOD=	mac_xac
SRCS=	vnode_if.h \
		mac_xac.c \
		config_loader.c \
		config_loader.h \
		xac_common.c \
		xac_common.h

.ifdef XAC_DEBUG
CFLAGS+= -DDEBUG
.endif

.include <bsd.kmod.mk>

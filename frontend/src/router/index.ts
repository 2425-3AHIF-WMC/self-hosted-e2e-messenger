import { createRouter, createWebHistory } from 'vue-router';
import type { RouteRecordRaw } from 'vue-router';
import { storageService } from '@/services/storage.service';

import LoginPage from '../LoginPage.vue';
import RegisterPage from '../RegisterPage.vue';
import AppSidebar from '../components/AppSidebar.vue';

const routes: RouteRecordRaw[] = [
    {
        path: '/',
        name: 'home',
        component: AppSidebar,
        meta: { requiresAuth: true }
    },
    {
        path: '/login',
        name: 'login',
        component: LoginPage
    },
    {
        path: '/register',
        name: 'register',
        component: RegisterPage
    },
    {
        path: '/:pathMatch(.*)*',
        redirect: '/'
    }
];

const router = createRouter({
    history: createWebHistory(),
    routes
});

router.beforeEach((to, _, next) => {
    const isAuthenticated = storageService.isAuthenticated();

    if (to.meta.requiresAuth && !isAuthenticated) {
        next('/login');
    } else if ((to.path === '/login' || to.path === '/register') && isAuthenticated) {
        next('/');
    } else {
        next();
    }
});

export default router;

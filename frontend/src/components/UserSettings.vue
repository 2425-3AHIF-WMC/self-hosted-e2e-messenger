<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { Button } from '@/components/ui/button';
import { storageService } from '@/services/storage.service';
import UserSettingsPage from '@/components/settings/UserSettingsPage.vue';
import PrivacySettingsPage from '@/components/settings/PrivacySettingsPage.vue';
import KeyManagementPage from '@/components/settings/KeyManagementPage.vue';
import MessageStoragePage from '@/components/settings/MessageStoragePage.vue';
import ConfirmDialog from '@/components/ConfirmDialog.vue';

const router = useRouter();
const activeSection = ref('user'); // 'user', 'privacy', 'keys', 'messages'
const showLogoutConfirm = ref(false);

// Function to handle navigation between sections
function navigateTo(section: string) {
  activeSection.value = section;
}

function logout() {
  // Clear all data including messages
  storageService.clearAuth();
  localStorage.removeItem('local_message_storing');
  localStorage.clear(); // Clear everything else
  router.push('/login');
}

function confirmLogout() {
  showLogoutConfirm.value = true;
}
</script>

<template>
  <div class="w-full h-full flex">
    <!-- Settings sidebar -->
    <div class="w-64 bg-card border-r border-border flex flex-col h-full">
      <!-- Navigation sections -->
      <div class="overflow-y-auto flex-grow p-2">
        <!-- User Settings -->
        <button 
          @click="navigateTo('user')" 
          class="w-full text-left p-2 px-4 rounded-md hover:bg-accent hover:text-accent-foreground transition-colors mb-1"
          :class="{ 'bg-accent text-accent-foreground': activeSection === 'user' }"
        >
          <div class="font-medium">My Account</div>
        </button>

        <!-- Privacy Settings -->
        <button 
          @click="navigateTo('privacy')" 
          class="w-full text-left p-2 px-4 rounded-md hover:bg-accent hover:text-accent-foreground transition-colors mb-1"
          :class="{ 'bg-accent text-accent-foreground': activeSection === 'privacy' }"
        >
          <div class="font-medium">Privacy Settings</div>
        </button>

        <!-- Message Storage -->
        <button 
          @click="navigateTo('messages')" 
          class="w-full text-left p-2 px-4 rounded-md hover:bg-accent hover:text-accent-foreground transition-colors mb-1"
          :class="{ 'bg-accent text-accent-foreground': activeSection === 'messages' }"
        >
          <div class="font-medium">Message Storage</div>
        </button>

        <!-- Key Management -->
        <button 
          @click="navigateTo('keys')" 
          class="w-full text-left p-2 px-4 rounded-md hover:bg-accent hover:text-accent-foreground transition-colors mb-1"
          :class="{ 'bg-accent text-accent-foreground': activeSection === 'keys' }"
        >
          <div class="font-medium">Key Management</div>
        </button>
      </div>
      
      <!-- Logout Button -->
      <div class="p-2 pb-8 mt-auto border-t border-border">
        <Button variant="destructive" @click="confirmLogout" class="w-full">
          Log Out
        </Button>
      </div>
    </div>
    
    <!-- Main content area -->
    <div class="flex-1 overflow-auto p-6">
      <!-- Render the appropriate component based on activeSection -->
      <UserSettingsPage v-if="activeSection === 'user'" />
      <PrivacySettingsPage v-if="activeSection === 'privacy'" />
      <MessageStoragePage v-if="activeSection === 'messages'" />
      <div v-if="activeSection === 'keys'">
        <KeyManagementPage />
      </div>
    </div>
  </div>
  
  <!-- Confirm Logout Dialog -->
  <ConfirmDialog
    v-model:show="showLogoutConfirm"
    title="Confirm Logout"
    message="Are you sure you want to log out? This will clear all locally stored messages and data."
    confirmLabel="Logout"
    @confirm="logout"
  />
</template>

<style scoped>
/* Just keeping minimal styles */
.max-w-3xl {
  margin-top: 0;
}
</style>


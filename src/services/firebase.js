/**
 * Firebase Service
 * Handles Firebase initialization and configuration
 * OWASP A05:2021 - Security Misconfiguration (env variables)
 */

import { initializeApp } from 'firebase/app';
import { getAuth, signInAnonymously, onAuthStateChanged, signOut } from 'firebase/auth';
import { getFirestore, doc, setDoc, getDoc, collection, onSnapshot, query, orderBy, limit } from 'firebase/firestore';

// Firebase configuration from environment variables
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID,
};

// Check if Firebase is configured
const isFirebaseConfigured = () => {
  return !!(firebaseConfig.apiKey && firebaseConfig.projectId);
};

// Initialize Firebase only if configured
let app = null;
let auth = null;
let db = null;

if (isFirebaseConfigured()) {
  try {
    app = initializeApp(firebaseConfig);
    auth = getAuth(app);
    db = getFirestore(app);
  } catch (error) {
    console.error('Firebase initialization error:', error);
  }
}

/**
 * Sign in anonymously
 * @returns {Promise<Object>} User object
 */
export const signInAnon = async () => {
  if (!auth) {
    console.warn('Firebase not configured. Using local storage only.');
    return null;
  }

  try {
    const result = await signInAnonymously(auth);
    return result.user;
  } catch (error) {
    console.error('Anonymous sign-in error:', error);
    return null;
  }
};

/**
 * Sign out current user
 * @returns {Promise<void>}
 */
export const signOutUser = async () => {
  if (!auth) return;

  try {
    await signOut(auth);
  } catch (error) {
    console.error('Sign out error:', error);
  }
};

/**
 * Subscribe to auth state changes
 * @param {Function} callback - Callback function
 * @returns {Function} Unsubscribe function
 */
export const subscribeToAuthState = (callback) => {
  if (!auth) {
    callback(null);
    return () => {};
  }

  return onAuthStateChanged(auth, callback);
};

/**
 * Save user progress to Firestore
 * @param {string} userId - User ID
 * @param {Object} progress - Progress data
 * @returns {Promise<boolean>} Success status
 */
export const saveUserProgress = async (userId, progress) => {
  if (!db || !userId) {
    // Fall back to localStorage
    try {
      localStorage.setItem(`detectsim_progress_${userId || 'local'}`, JSON.stringify(progress));
      return true;
    } catch {
      return false;
    }
  }

  try {
    const userDocRef = doc(db, 'users', userId, 'data', 'progress');
    await setDoc(userDocRef, {
      ...progress,
      updatedAt: Date.now(),
    }, { merge: true });
    return true;
  } catch (error) {
    console.error('Save progress error:', error);
    // Fall back to localStorage
    try {
      localStorage.setItem(`detectsim_progress_${userId}`, JSON.stringify(progress));
      return true;
    } catch {
      return false;
    }
  }
};

/**
 * Load user progress from Firestore
 * @param {string} userId - User ID
 * @returns {Promise<Object|null>} Progress data
 */
export const loadUserProgress = async (userId) => {
  if (!db || !userId) {
    // Fall back to localStorage
    try {
      const data = localStorage.getItem(`detectsim_progress_${userId || 'local'}`);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  }

  try {
    const userDocRef = doc(db, 'users', userId, 'data', 'progress');
    const docSnap = await getDoc(userDocRef);

    if (docSnap.exists()) {
      return docSnap.data();
    }
    return null;
  } catch (error) {
    console.error('Load progress error:', error);
    // Fall back to localStorage
    try {
      const data = localStorage.getItem(`detectsim_progress_${userId}`);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  }
};

/**
 * Subscribe to user progress changes
 * @param {string} userId - User ID
 * @param {Function} callback - Callback function
 * @returns {Function} Unsubscribe function
 */
export const subscribeToProgress = (userId, callback) => {
  if (!db || !userId) {
    // Load from localStorage once
    try {
      const data = localStorage.getItem(`detectsim_progress_${userId || 'local'}`);
      callback(data ? JSON.parse(data) : null);
    } catch {
      callback(null);
    }
    return () => {};
  }

  const userDocRef = doc(db, 'users', userId, 'data', 'progress');

  return onSnapshot(userDocRef, (docSnap) => {
    if (docSnap.exists()) {
      callback(docSnap.data());
    } else {
      callback(null);
    }
  }, (error) => {
    console.error('Progress subscription error:', error);
    callback(null);
  });
};

/**
 * Update leaderboard entry
 * @param {string} userId - User ID
 * @param {Object} data - Leaderboard data
 * @returns {Promise<boolean>} Success status
 */
export const updateLeaderboard = async (userId, data) => {
  if (!db || !userId) return false;

  try {
    const lbDocRef = doc(db, 'leaderboard', userId);
    await setDoc(lbDocRef, {
      ...data,
      updatedAt: Date.now(),
    }, { merge: true });
    return true;
  } catch (error) {
    console.error('Update leaderboard error:', error);
    return false;
  }
};

/**
 * Subscribe to leaderboard changes
 * @param {Function} callback - Callback function
 * @param {number} limitCount - Number of entries to fetch
 * @returns {Function} Unsubscribe function
 */
export const subscribeToLeaderboard = (callback, limitCount = 10) => {
  if (!db) {
    callback([]);
    return () => {};
  }

  const lbQuery = query(
    collection(db, 'leaderboard'),
    orderBy('score', 'desc'),
    limit(limitCount)
  );

  return onSnapshot(lbQuery, (snapshot) => {
    const entries = [];
    snapshot.forEach((doc) => {
      entries.push({ id: doc.id, ...doc.data() });
    });
    callback(entries);
  }, (error) => {
    console.error('Leaderboard subscription error:', error);
    callback([]);
  });
};

export {
  app,
  auth,
  db,
  isFirebaseConfigured,
};

export default {
  signInAnon,
  signOutUser,
  subscribeToAuthState,
  saveUserProgress,
  loadUserProgress,
  subscribeToProgress,
  updateLeaderboard,
  subscribeToLeaderboard,
  isFirebaseConfigured,
};

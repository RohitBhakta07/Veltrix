import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from 'react-router-dom';
import { AuthProvider } from './features/auth/AuthProvider';
import { router } from './app/router';
import { ThemeProvider } from './theme/ThemeProvider';
import { RevealProvider } from './reveal/RevealProvider';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5000,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <RevealProvider>
          <AuthProvider>
            <RouterProvider router={router} />
          </AuthProvider>
        </RevealProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

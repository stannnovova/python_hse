# from typing import List

# height = list(map(int, input()))

# def maxArea(height: List[int]) -> int:
#     left = 0
#     right = len(height) - 1
#     maxx = 0

#     while(left < right):

#         current_area = min(height[left], height[right]) * (right - left)
#         maxx = max(current_area)

#         if height[left] < height[right]:
#             left += 1

#         else:
#             right +=1

#     return(maxx)

